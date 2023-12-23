package formsauth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path"
	"time"

	"go.uber.org/zap"
)

const (
	cookieName       = "caddyauth"
	cookieAge        = 14 * 24 * time.Hour
	cookieRefreshAge = 24 * time.Hour
	sessionIdLen     = 64
	sessionGcTick    = time.Hour
)

// initSessionsDir ensures SessionsDir exists and starts background garbage collection.
func (fa *FormsAuth) initSessionsDir() error {
	if err := os.MkdirAll(fa.SessionsDir, 0700); err != nil {
		return err
	}

	ticker := time.NewTicker(sessionGcTick)
	go func() {
		for {
			fa.sessionGc()
			<-ticker.C
		}
	}()

	return nil
}

// sessionGc deletes expired session files.
func (fa *FormsAuth) sessionGc() {
	entries, err := os.ReadDir(fa.SessionsDir)
	if err != nil {
		fa.logger.Error("reading sessions directory", zap.String("sessions_dir", fa.SessionsDir), zap.Error(err))
	}

	now := time.Now()
	for _, entry := range entries {
		sessionPath := path.Join(fa.SessionsDir, entry.Name())
		sessionData, err := os.ReadFile(sessionPath)
		if err != nil {
			fa.logger.Error("reading session file", zap.String("file", sessionPath), zap.Error(err))
			continue
		}

		var session Session
		if err := json.Unmarshal(sessionData, &session); err != nil {
			fa.logger.Error("unmarshalling session file", zap.String("file", sessionPath), zap.Error(err))
			continue
		}

		if !now.Before(session.Expires) {
			os.Remove(sessionPath)
		}
	}
}

// initSession creates a unique session file and sets the cookie.
func (fa *FormsAuth) initSession(w http.ResponseWriter, username string) error {
	now := time.Now()
	session := Session{
		Username:  username,
		Refreshes: now.Add(cookieRefreshAge),
		Expires:   now.Add(cookieAge),
	}

	var file *os.File
	sessionIdBytes := make([]byte, sessionIdLen/2)
	for {
		var err error
		if _, err = rand.Read(sessionIdBytes); err != nil {
			return err
		}

		session.Id = hex.EncodeToString(sessionIdBytes)
		sessionPath := path.Join(fa.SessionsDir, session.Id)
		file, err = os.OpenFile(sessionPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
	}

	sessionData, err := json.Marshal(&session)
	if err == nil {
		_, err = file.Write(sessionData)
	}
	if err2 := file.Close(); err == nil {
		err = err2
	}
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    session.Id,
		Path:     "/",
		MaxAge:   int(cookieAge.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// loadSession loads the session identified by the cookie.
func (fa *FormsAuth) loadSession(w http.ResponseWriter, r *http.Request) *Session {
	sessionPath := fa.sessionPathForCookie(r)
	if sessionPath == "" {
		return nil
	}

	sessionData, err := os.ReadFile(sessionPath)
	if err != nil {
		return nil
	}

	var session Session
	if err := json.Unmarshal(sessionData, &session); err != nil {
		fa.logger.Error("unmarshalling session file", zap.String("file", sessionPath), zap.Error(err))
		return nil
	}

	now := time.Now()
	if !now.Before(session.Expires) {
		os.Remove(sessionPath)
		return nil
	}

	if !now.Before(session.Refreshes) {
		session.Refreshes = now.Add(cookieRefreshAge)
		session.Expires = now.Add(cookieAge)

		var file *os.File
		sessionPath := path.Join(fa.SessionsDir, session.Id)
		sessionData, err := json.Marshal(session)
		if err == nil {
			file, err = os.CreateTemp(fa.SessionsDir, ".tmp-")
		}
		if err == nil {
			_, err = file.Write(sessionData)
		}
		if file != nil {
			if err2 := file.Close(); err == nil {
				err = err2
			}
		}
		if err == nil {
			err = os.Rename(file.Name(), sessionPath)
		}

		if err == nil {
			http.SetCookie(w, &http.Cookie{
				Name:     cookieName,
				Value:    session.Id,
				Path:     "/",
				MaxAge:   int(cookieAge.Seconds()),
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
		} else {
			fa.logger.Error("writing session file", zap.String("file", sessionPath), zap.Error(err))
			if file != nil {
				os.Remove(file.Name())
			}
		}
	}

	return &session
}

// destroySession deletes the session file and the cookie.
func (fa *FormsAuth) destroySession(w http.ResponseWriter, r *http.Request) {
	sessionPath := fa.sessionPathForCookie(r)
	if sessionPath != "" {
		os.Remove(sessionPath)
	}

	clearCookie(w)
}

// sessionPathForCookie validates the cookie and returns the path to the session file.
func (fa *FormsAuth) sessionPathForCookie(r *http.Request) string {
	cookie, _ := r.Cookie(cookieName)
	if cookie == nil || len(cookie.Value) != sessionIdLen {
		return ""
	}
	for _, c := range cookie.Value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ""
		}
	}

	return path.Join(fa.SessionsDir, cookie.Value)
}

// clearCookie sets a cookie header that clears the session cookie.
func clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
