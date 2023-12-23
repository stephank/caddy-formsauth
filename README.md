# caddy-formsauth

This is a [Caddy] module that implements simple form-based authentication.

[Caddy]: https://caddyserver.com/

- Uses traditional sessions, with simple filesystem storage.
- Configuration intended to resemble [basicauth].

[basicauth]: https://caddyserver.com/docs/caddyfile/directives/basicauth

```
my-app.example

route {
  formsauth {
    # This path is captured to serve the login form.
    login_route /_login
    # Where to store session files.
    sessions_dir /var/lib/caddy/formsauth-sessions/my-app
    # A list of usernames and hashed passwords, like basicauth.
    users {
      stephank $2a$14$nA45/1wl4DoSUNi8ZbdAluk/OFTWqnnaJbMcH1PabrYLj.otmgsnK
    }
  }
  reverse_proxy 127.0.0.1:3000 {
    # Provide the username to the backend.
    header_up X-Remote-User "{http.auth.user.id}"
  }
}
```

### Alternatives

- [caddy-security](https://github.com/greenpau/caddy-security)
