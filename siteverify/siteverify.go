// Package siteverify provides utilities for verifying a token contains the
// expected site.
package siteverify

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/RMI/credential-service/allowlist"
	"github.com/go-chi/jwtauth/v5"
	"go.uber.org/zap"
)

func CheckSite(site allowlist.Site, logger zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, claims, err := jwtauth.FromContext(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			if claims == nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			siteClaimI, ok := claims["sites"]
			if !ok {
				logger.Info("JWT claims had no 'sites' claim")
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			siteClaim, ok := siteClaimI.(string)
			if !ok {
				logger.Info("JWT 'sites' claim had unexpected type", zap.String("type", fmt.Sprintf("%T", siteClaimI)))
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			if !isClaimValidForSite(siteClaim, site) {
				logger.Info("JWT 'sites' claim was invalid", zap.String("claim", siteClaim))
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			// Token has the correct site, pass it through
			next.ServeHTTP(w, r)
		})
	}
}

func isClaimValidForSite(siteClaim string, target allowlist.Site) bool {
	if siteClaim == "all" {
		return true
	}

	for _, s := range strings.Split(siteClaim, ",") {
		if s == string(target) {
			return true
		}
	}
	return false
}
