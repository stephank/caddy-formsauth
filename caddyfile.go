package formsauth

import (
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
)

// initConfig registers the Caddyfile parser.
func initConfig() {
	httpcaddyfile.RegisterHandlerDirective("formsauth", parseCaddyfile)
}

// parseCaddyfile parses formsauth directivess in a Caddyfile.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var fa FormsAuth

	h.Next()
	if h.NextArg() {
		return nil, h.ArgErr()
	}

	hashName := "bcrypt"
	for h.NextBlock(0) {
		switch h.Val() {
		case "login_route":
			h.Args(&fa.LoginRoute)
			if h.NextArg() {
				return nil, h.ArgErr()
			}
			if fa.LoginRoute == "" {
				return nil, h.Err("login_route cannot be empty or missing")
			}

		case "sessions_dir":
			h.Args(&fa.SessionsDir)
			if h.NextArg() {
				return nil, h.ArgErr()
			}
			if fa.SessionsDir == "" {
				return nil, h.Err("sessions_dir cannot be empty or missing")
			}

		case "users":
			if h.NextArg() {
				hashName = h.Val()
			}
			if h.NextArg() {
				return nil, h.ArgErr()
			}

			fa.Accounts = make(map[string]string)
			for h.NextBlock(1) {
				username := h.Val()

				var password string
				h.Args(&password)
				if h.NextArg() {
					return nil, h.ArgErr()
				}

				if username == "" || password == "" {
					return nil, h.Err("username and password cannot be empty or missing")
				}

				fa.Accounts[username] = password
			}

		default:
			return nil, h.Errf("unknown subdirective '%s'", h.Val())
		}
	}

	var cmp caddyauth.Comparer
	switch hashName {
	case "bcrypt":
		cmp = caddyauth.BcryptHash{}
	case "scrypt":
		cmp = caddyauth.ScryptHash{}
	default:
		return nil, h.Errf("unrecognized hash algorithm: %s", h.Val())
	}
	fa.HashRaw = caddyconfig.JSONModuleObject(cmp, "algorithm", hashName, nil)

	return &fa, nil
}
