// Package httpreq provides basic middleware for allowing OpenAPI endpoint
// handlers to access raw *http.Request fields.
package httpreq

import (
	"context"
	"net/http"
)

type ctxKey struct{}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ctxKey{}, r)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func FromContext(ctx context.Context) (*http.Request, bool) {
	val, ok := ctx.Value(ctxKey{}).(*http.Request)
	if !ok {
		return nil, false
	}
	return val, true
}
