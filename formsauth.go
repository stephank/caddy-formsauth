package formsauth

import (
	_ "embed"
	"fmt"
	"time"

	"encoding/json"
	"net/http"
	"net/url"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"go.uber.org/zap"
)

const (
	cacheControl     = "Cache-Control"
	cacheControlNone = "private, no-cache, no-store, max-age=0"
)

func init() {
	initTemplate()
	initConfig()
	caddy.RegisterModule(&FormsAuth{})
}

// FormsAuth is the model for a formsauth directive.
type FormsAuth struct {
	// The path where the login form is served.
	LoginRoute string `json:"loginRoute"`

	// Directory where session files are stored.
	SessionsDir string `json:"sessionsDir"`

	// The algorithm with which the passwords are hashed. Default: bcrypt
	HashRaw json.RawMessage `json:"hash,omitempty" caddy:"namespace=http.authentication.hashes inline_key=algorithm"`

	// The list of accounts to authenticate.
	Accounts map[string]string `json:"accounts,omitempty"`

	logger       *zap.Logger
	hash         caddyauth.Comparer
	fakePassword []byte
}

// Session is the model for JSON session files.
type Session struct {
	Id        string    `json:"id"`
	Username  string    `json:"username"`
	Refreshes time.Time `json:"refreshes"`
	Expires   time.Time `json:"expires"`
}

func (*FormsAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.formsauth",
		New: func() caddy.Module { return new(FormsAuth) },
	}
}

func (fa *FormsAuth) Provision(ctx caddy.Context) error {
	if fa.LoginRoute == "" {
		return fmt.Errorf("login_route cannot be empty or missing")
	}
	if fa.SessionsDir == "" {
		return fmt.Errorf("sessions_dir cannot be empty or missing")
	}
	if fa.HashRaw == nil {
		fa.HashRaw = json.RawMessage(`{"algorithm": "bcrypt"}`)
	}
	if fa.Accounts == nil {
		fa.Accounts = make(map[string]string)
	}

	fa.logger = ctx.Logger()

	// load password hasher
	hasherIface, err := ctx.LoadModule(fa, "HashRaw")
	if err != nil {
		return fmt.Errorf("loading password hasher module: %v", err)
	}
	fa.hash = hasherIface.(caddyauth.Comparer)
	if fa.hash == nil {
		return fmt.Errorf("hash is required")
	}

	// if supported, generate a fake password we can compare against if needed
	if hasher, ok := fa.hash.(caddyauth.Hasher); ok {
		fa.fakePassword = hasher.FakeHash()
	}

	return fa.initSessionsDir()
}

func (fa *FormsAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.URL.Path == fa.LoginRoute {
		w.Header().Add(cacheControl, cacheControlNone)

		switch r.Method {
		case http.MethodGet:
			// Simply render the login page.
			return loginTemplate.Execute(w, LoginContext{
				LoginRoute: fa.LoginRoute,
				ReturnTo:   r.URL.Query().Get("returnTo"),
			})

		case http.MethodPost:
			if r.FormValue("delete") != "" {
				// App logout request via HTML form.
				fa.destroySession(w, r)
				// Redirect back to the login form.
				loc := url.URL{Path: fa.LoginRoute}
				if returnTo := r.FormValue("returnTo"); returnTo != "" {
					loc.RawQuery = "returnTo=" + url.QueryEscape(returnTo)
				}
				w.Header().Add("Location", loc.String())
				w.WriteHeader(http.StatusFound)
				return nil
			} else {
				// App login request via HTML form.
				return fa.attemptLogin(w, r)
			}

		case http.MethodDelete:
			// App logout request via XHR.
			fa.destroySession(w, r)
			w.WriteHeader(http.StatusNoContent)
			return nil

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return nil
		}
	}

	// Middleware path, check if authenticated.
	if session := fa.loadSession(w, r); session != nil {
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		repl.Set("http.auth.user.id", session.Username)
		return next.ServeHTTP(w, r)
	}

	// If not, render login form.
	clearCookie(w)
	w.Header().Add(cacheControl, cacheControlNone)
	w.WriteHeader(http.StatusForbidden)
	return loginTemplate.Execute(w, LoginContext{
		LoginRoute: fa.LoginRoute,
		ReturnTo:   r.URL.String(),
	})
}

// attemptLogin validates a POST request to the login route.
func (fa *FormsAuth) attemptLogin(w http.ResponseWriter, r *http.Request) error {
	username := r.FormValue("username")
	password := r.FormValue("password")

	hashedPasswordString, hasAccount := fa.Accounts[username]
	var hashedPassword []byte
	if hasAccount {
		hashedPassword = []byte(hashedPasswordString)
	} else {
		hashedPassword = fa.fakePassword
	}

	ok, err := fa.hash.Compare(hashedPassword, []byte(password), nil)
	if err != nil {
		return err
	}

	if !hasAccount || !ok {
		// Login failed.
		w.WriteHeader(http.StatusForbidden)
		return loginTemplate.Execute(w, LoginContext{
			LoginRoute: fa.LoginRoute,
			ReturnTo:   r.FormValue("returnTo"),
		})
	}

	if err := fa.initSession(w, username); err != nil {
		return err
	}

	returnTo := ""
	returnToURL, _ := url.Parse(r.FormValue("returnTo"))
	if returnToURL != nil {
		// Don't allow redirecting off-site.
		returnToURL.Scheme = ""
		returnToURL.Opaque = ""
		returnToURL.User = nil
		returnToURL.Host = ""
		returnTo = returnToURL.String()
	}
	if returnTo == "" {
		returnTo = "/"
	}
	w.Header().Add("Location", returnTo)
	w.WriteHeader(http.StatusFound)
	return nil
}

var (
	_ caddy.Module                = (*FormsAuth)(nil)
	_ caddy.Provisioner           = (*FormsAuth)(nil)
	_ caddyhttp.MiddlewareHandler = (*FormsAuth)(nil)
)
