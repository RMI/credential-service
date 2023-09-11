// Package azjwt implements JWT authentication against Azure, which has some
// minor peculiarities that require special handling, see
// https://github.com/lestrrat-go/jwx/issues/395
package azjwt

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/RMI/credential-service/allowlist"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.uber.org/zap"
)

type Auth struct {
	cache    *jwk.Cache
	endpoint string
	logger   *zap.Logger

	allowlist *allowlist.Checker

	aud    string
	iss    string
	policy string
}

type Config struct {
	Logger *zap.Logger

	// Tenant is the name of the directory that users are logging into, should be a lowercase alphanum string
	Tenant string
	// TenantID (also called the directory ID), is used as the issuer ('iss' claim) in JWTs, formatted as a UUID
	TenantID string
	// Policy is the name of the user flow/policy, usually named B2C_<number>_<name>
	Policy string
	// ClientID (also called the application ID) is used as the audience ('aud' claim) in JWTs, formatted as a UUID
	ClientID string

	Allowlist *allowlist.Checker
}

func (c *Config) validate() error {
	if c.Logger == nil {
		return errors.New("no *zap.Logger was provided")
	}

	if c.Tenant == "" {
		return errors.New("no tenant was provided")
	}
	if c.TenantID == "" {
		return errors.New("no tenantID was provided")
	}
	if c.Policy == "" {
		return errors.New("no policy was provided")
	}
	if c.ClientID == "" {
		return errors.New("no clientID was provided")
	}

	if c.Allowlist == nil {
		return errors.New("no *allowlist.Checker was provided")
	}

	return nil
}

// NewAuth returns a client capable of verifying JWT tokens from Microsoft AD B2C.
func NewAuth(ctx context.Context, cfg *Config) (*Auth, error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	// See also https://<tenant>.b2clogin.com/<tenant>.onmicrosoft.com/<policy>/v2.0/.well-known/openid-configuration
	endpoint := fmt.Sprintf("https://%s.b2clogin.com/%s.onmicrosoft.com/%s/discovery/v2.0/keys", cfg.Tenant, cfg.Tenant, cfg.Policy)
	cache := jwk.NewCache(ctx)
	if err := cache.Register(endpoint); err != nil {
		return nil, fmt.Errorf("failed to register JWT key endpoint: %w", err)
	}
	if _, err := cache.Refresh(ctx, endpoint); err != nil {
		return nil, fmt.Errorf("failed to load key set from endpoint: %w", err)
	}
	return &Auth{
		cache:     cache,
		endpoint:  endpoint,
		logger:    cfg.Logger,
		allowlist: cfg.Allowlist,

		aud:    cfg.ClientID,
		iss:    fmt.Sprintf("https://%s.b2clogin.com/%s/v2.0/", cfg.Tenant, cfg.TenantID),
		policy: cfg.Policy,
	}, nil
}

func (a *Auth) Verifier(next http.Handler) http.Handler {
	hfn := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		existingTkn, _, _ := jwtauth.FromContext(ctx)
		// Previous middleware has already set up auth, continue
		if existingTkn != nil {
			next.ServeHTTP(w, r)
			return
		}
		tkn, err := a.parseAndVerify(ctx, r)
		ctx = jwtauth.NewContext(ctx, tkn, err)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(hfn)
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

		// Now, check against the allowlist
		allowedEmails, err := a.checkEmailAllowed(token)
		if err != nil {
			a.logger.Warn("token failed allowlist check", zap.Error(err))
			if errors.Is(err, errNotAllowlisted) {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			} else {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			}
			return
		}

		// Add the email to the context so that it can be used by the handler
		ctx := context.WithValue(r.Context(), emailContextKey{}, allowedEmails[0])
		// Token is authenticated, pass it through
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(hfn)
}

type emailContextKey struct{}

func EmailFromContext(ctx context.Context) (string, error) {
	email, ok := ctx.Value(emailContextKey{}).(string)
	if !ok {
		return "", fmt.Errorf("no email found in context")
	}
	return email, nil
}

func (a *Auth) parseAndVerify(ctx context.Context, r *http.Request) (jwt.Token, error) {
	// We only accept the token in the header, as opposed to actual end-user APIs,
	// which will accept the token in the header ('Authorization: BEARER <tkn>') or in
	// a cookie ('jwt=<tkn> ...')
	tknStr := jwtauth.TokenFromHeader(r)
	if tknStr == "" {
		return nil, jwtauth.ErrNoTokenFound
	}

	keySet, err := a.cache.Get(ctx, a.endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to load Microsoft auth key set from cache: %w", err)
	}

	// This is needed because Microsoft doesn't include the "alg" header in their
	// keyset descriptions, see https://github.com/lestrrat-go/jwx/issues/395
	// We know the algorithm in use is 256-bit RSA, so we set that manually so that
	// jwt.Parse correctly matches up the keys below.
	// The alternative would be to use jwt.InferAlgorithmFromKey(), but that
	// involves just trying algos until one works, which isn't great.
	ks := jwk.NewSet()
	ki := keySet.Keys(ctx)
	for ki.Next(ctx) {
		k, ok := ki.Pair().Value.(jwk.Key)
		if !ok {
			return nil, fmt.Errorf("failed to load key from key set, had type %T", ki.Pair().Value)
		}
		if err := k.Set("alg", "RS256"); err != nil {
			return nil, fmt.Errorf("failed to set 'alg' on key %q: %w", k.KeyID(), err)
		}
		if err := ks.AddKey(k); err != nil {
			return nil, fmt.Errorf("failed to add key %q to key set: %w", k.KeyID(), err)
		}
	}

	opts := []jwt.ParseOption{
		// See https://learn.microsoft.com/en-us/azure/active-directory-b2c/tokens-overview#validate-claims
		// TODO: Consider verifying the 'nonce' claim as well.
		jwt.WithKeySet(ks),
		jwt.WithAudience(a.aud),
		jwt.WithIssuer(a.iss),
		jwt.WithValidate(true),
		jwt.WithClaimValue("tfp", a.policy),
	}

	tkn, err := jwt.Parse([]byte(tknStr), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to validate token against key set: %w", err)
	}

	return tkn, nil
}

var errNotAllowlisted = errors.New("email isn't allowlisted")

func (a *Auth) checkEmailAllowed(tkn jwt.Token) ([]string, error) {
	// See https://learn.microsoft.com/en-us/azure/active-directory/develop/id-token-claims-reference
	emailsVal, ok := tkn.Get("emails")
	if !ok {
		return nil, errors.New("token didn't contain an 'emails' claim")
	}
	emailsI, ok := emailsVal.([]any)
	if !ok {
		return nil, fmt.Errorf("'emails' claim in token had unexpected type %T", emailsVal)
	}

	var emails []string
	for i, ei := range emailsI {
		email, ok := ei.(string)
		if !ok {
			return nil, fmt.Errorf("email %d from 'emails' claim in token had unexpected type %T", i, ei)
		}
		emails = append(emails, email)
	}

	// If one of their emails is allowed, consider them allowed.
	allowed := a.allowedEmails(emails)
	if len(allowed) == 0 {
		return nil, errNotAllowlisted
	}

	return allowed, nil
}

func (a *Auth) allowedEmails(emails []string) []string {
	var result []string
	for _, email := range emails {
		allowed, err := a.allowlist.Check(email)
		if err != nil {
			a.logger.Warn("failed to check allowlist", zap.String("email", email), zap.Error(err))
			continue
		}
		// We don't return early on success, just to parse and validate all emails in the token.
		if allowed {
			result = append(result, email)
		}
	}
	return result
}
