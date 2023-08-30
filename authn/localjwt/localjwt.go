// Package localjwt implements JWT authentication using local keys, which is
// meant for local development.
package localjwt

import (
	"fmt"
	"net/http"

	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.uber.org/zap"
)

type Auth struct {
	jwtAuth  *jwtauth.JWTAuth
	logger   *zap.Logger
	Verifier func(next http.Handler) http.Handler
}

func NewAuth(jwtAuth *jwtauth.JWTAuth, logger *zap.Logger) *Auth {
	return &Auth{
		jwtAuth:  jwtAuth,
		logger:   logger,
		Verifier: jwtauth.Verifier(jwtAuth),
	}
}

func (a *Auth) Authenticator(next http.Handler) http.Handler {
	hfn := func(w http.ResponseWriter, r *http.Request) {
		// Skip auth verification if they're logging out.
		if r.URL.Path == "/logout/cookie" && r.Method == http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}

		token, _, err := jwtauth.FromContext(r.Context())

		if err != nil {
			a.logger.Warn("token failed validation", zap.Error(err))
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if token == nil {

			a.logger.Warn("no token found in request", zap.Error(err))
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		}

		if err := jwt.Validate(token); err != nil {
			a.logger.Warn("token failed validation", zap.Error(err))
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// In local auth, we expect an additional claim indicating that this was
		// generated explicitly for the purpose of being exchanged.
		val, ok := token.Get("local_auth")
		if !ok {
			http.Error(w, "no 'local_auth' claim in source token", http.StatusUnauthorized)
			return
		}
		valB, ok := val.(bool)
		if !ok {
			http.Error(w, fmt.Sprintf("'local_auth' claim had type %T", val), http.StatusInternalServerError)
			return
		}
		if !valB {
			// This shouldn't happen. Either the claim isn't there, or it's set to `true`.
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// Token is authenticated, pass it through
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(hfn)
}
