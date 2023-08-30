package testcredsrv

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/RMI/credential-service/httpreq"
	"github.com/RMI/credential-service/openapi/testcreds"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type Server struct {
	Now     func() time.Time
	JWTAuth *jwtauth.JWTAuth
}

func (s *Server) CheckCredentials(ctx context.Context, req testcreds.CheckCredentialsRequestObject) (testcreds.CheckCredentialsResponseObject, error) {
	r, ok := httpreq.FromContext(ctx)
	if !ok {
		return testcreds.CheckCredentialsdefaultJSONResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       testcreds.Error{Message: http.StatusText(http.StatusInternalServerError)},
		}, nil
	}

	tknStr, ok := getTokenString(r)
	if !ok {
		return testcreds.CheckCredentials200JSONResponse{
			FailureReason: ptr("no token found in the 'Authorization' header or 'jwt' cookie"),
			Valid:         false,
		}, nil
	}

	tkn, err := s.JWTAuth.Decode(tknStr)
	if err != nil {
		return testcreds.CheckCredentials200JSONResponse{
			FailureReason: ptr(fmt.Sprintf("failed to decode token: %v", err)),
			Valid:         false,
		}, nil
	}

	if tkn == nil {
		return testcreds.CheckCredentialsdefaultJSONResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       testcreds.Error{Message: http.StatusText(http.StatusInternalServerError)},
		}, nil
	}

	if _, ok := tkn.Get("local_auth"); ok {
		// If you get this error, it's because you're using a 'source' JWT, which is a
		// stand-in for an auth system (e.g. Azure AD, Auth0, etc) issued ID token.
		return testcreds.CheckCredentials200JSONResponse{
			FailureReason: ptr("'source' auth token used as end-user API token"),
			Valid:         false,
		}, nil
	}

	if err := jwt.Validate(tkn); err != nil {
		return responseForValidationError(err), nil
	}

	return testcreds.CheckCredentials200JSONResponse{
		Valid:   true,
		UserID:  ptr(tkn.Subject()),
		TokenID: ptr(tkn.JwtID()),
	}, nil
}

func responseForValidationError(err error) testcreds.CheckCredentialsResponseObject {
	switch {
	case errors.Is(err, jwt.ErrInvalidIssuedAt()):
		return testcreds.CheckCredentials200JSONResponse{
			FailureReason: ptr("token had invalid 'iat' (issued at) claim"),
			Valid:         false,
		}
	case errors.Is(err, jwt.ErrTokenExpired()):
		return testcreds.CheckCredentials200JSONResponse{
			FailureReason: ptr("token was expired"),
			Valid:         false,
		}
	case errors.Is(err, jwt.ErrTokenNotYetValid()):
		return testcreds.CheckCredentials200JSONResponse{
			FailureReason: ptr("token was not yet valid"),
			Valid:         false,
		}
	default:
		return testcreds.CheckCredentials200JSONResponse{
			FailureReason: ptr(fmt.Sprintf("failed to validate JWT: %v", err)),
			Valid:         false,
		}
	}
}

type findTokenFn func(r *http.Request) string

func getTokenString(r *http.Request) (string, bool) {
	for _, fn := range []findTokenFn{jwtauth.TokenFromHeader, jwtauth.TokenFromCookie} {
		tknStr := fn(r)
		if tknStr != "" {
			return tknStr, true
		}
	}
	return "", false
}

func ptr[T any](in T) *T {
	return &in
}
