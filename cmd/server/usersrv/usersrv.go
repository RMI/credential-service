// Package usersrv implements the User API interface,
// user.StrictServerInterface, which is auto-generated from the OpenAPI 3 spec,
// and describes a basic mechanism for exchanging auth provider (Firebase Auth,
// Cognito, Azure B2C, etc) tokens for app-specific tokens.
package usersrv

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/RMI/credential-service/openapi/user"
	"github.com/go-chi/jwtauth/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.uber.org/zap"
)

type TokenIssuer struct {
	Key jwk.Key
	Now func() time.Time
}

func (t *TokenIssuer) IssueToken(userID string, exp time.Time) (string, string, error) {
	now := t.Now()
	id := uuid.NewString()
	tkn, err := jwt.NewBuilder().
		Subject(userID).
		Audience([]string{"rmi.org"}).
		Expiration(exp).
		IssuedAt(now).
		NotBefore(now.Add(-time.Minute)).
		JwtID(id).
		Build()
	if err != nil {
		return "", "", fmt.Errorf("failed to build token: %w", err)
	}
	dat, err := jwt.Sign(tkn, jwt.WithKey(jwa.EdDSA, t.Key))
	if err != nil {
		return "", "", fmt.Errorf("failed to sign JWT: %w", err)
	}
	return string(dat), id, nil
}

type Server struct {
	Issuer *TokenIssuer
	Logger *zap.Logger
	Now    func() time.Time
}

// Exchange a user JWT token for an API key that can be used with other RMI APIs
// (POST /login/apikey)
func (s *Server) CreateAPIKey(ctx context.Context, req user.CreateAPIKeyRequestObject) (user.CreateAPIKeyResponseObject, error) {
	tkn, id, exp, err := s.exchangeToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	s.Logger.Info("issuing API key", zap.String("id", id))
	return user.CreateAPIKey200JSONResponse{
		Id:        id,
		Key:       tkn,
		ExpiresAt: &exp,
	}, nil
}

func (s *Server) exchangeToken(ctx context.Context) (string, string, time.Time, error) {
	_, srcClaims, err := jwtauth.FromContext(ctx)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to get auth service JWT to exchange for service-issued JWT: %w", err)
	}

	expC, ok := srcClaims["exp"]
	if !ok {
		return "", "", time.Time{}, errors.New("no 'exp' claim in source JWT")
	}

	exp, ok := expC.(time.Time)
	if !ok {
		return "", "", time.Time{}, fmt.Errorf("'exp' claim in source JWT was of type %T, expected a number", expC)
	}

	sub, ok := srcClaims["sub"]
	if !ok {
		return "", "", time.Time{}, errors.New("no 'sub' claim in source JWT")
	}

	subStr, ok := sub.(string)
	if !ok {
		return "", "", time.Time{}, fmt.Errorf("'sub' claim in source JWT was of type %T, expected a string", sub)
	}

	tkn, id, err := s.Issuer.IssueToken(subStr, exp)
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}

	return tkn, id, exp, nil
}

// Exchange a user JWT token for an auth cookie that can be used with other RMI APIs
// (POST /login/cookie)
func (s *Server) Login(ctx context.Context, req user.LoginRequestObject) (user.LoginResponseObject, error) {
	tkn, id, exp, err := s.exchangeToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}
	s.Logger.Info("issuing auth token", zap.String("id", id))

	c := http.Cookie{
		Name:     "jwt",
		Value:    tkn,
		Path:     "/",
		Expires:  exp,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	return user.Login200Response{
		Headers: user.Login200ResponseHeaders{
			SetCookie: c.String(),
		},
	}, nil
}

// Log out a user from RMI APIs
// (POST /logout/cookie)
func (s *Server) Logout(ctx context.Context, req user.LogoutRequestObject) (user.LogoutResponseObject, error) {
	c := http.Cookie{
		Name:     "jwt",
		Value:    "", // Clear it out
		Path:     "/",
		Expires:  s.Now().Add(-24 * time.Hour), // Already expired
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	return user.Logout200Response{
		Headers: user.Logout200ResponseHeaders{
			SetCookie: c.String(),
		},
	}, nil
}
