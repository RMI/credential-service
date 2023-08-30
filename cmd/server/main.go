// Command server runs the credential-exchanging service API.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/RMI/credential-service/allowlist"
	"github.com/RMI/credential-service/authn/localjwt"
	"github.com/RMI/credential-service/azure/azjwt"
	"github.com/RMI/credential-service/cmd/server/testcredsrv"
	"github.com/RMI/credential-service/cmd/server/usersrv"
	"github.com/RMI/credential-service/flagext"
	"github.com/RMI/credential-service/httpreq"
	"github.com/RMI/credential-service/keyutil"
	"github.com/RMI/credential-service/openapi/testcreds"
	"github.com/RMI/credential-service/openapi/user"
	"github.com/Silicon-Ally/zaphttplog"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/namsral/flag"
	"github.com/rs/cors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	oapimiddleware "github.com/deepmap/oapi-codegen/pkg/chi-middleware"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

func main() {
	if err := run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func checkFlags(rfs []requiredFlag) error {
	for _, rf := range rfs {
		if *rf.val == "" {
			return fmt.Errorf("--%s is required", rf.name)
		}
	}
	return nil
}

type requiredFlag struct {
	name string
	val  *string
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("args cannot be empty")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	var (
		port = fs.Int("port", 8080, "Port for test HTTP server")
		env  = fs.String("env", "", "the name of the environment we're running in, e.g. 'local', 'dev', 'prod'")

		rateLimitMaxRequests = fs.Int("rate_limit_max_requests", 100, "The maximum number of requests to allow per rate_limit_unit_time before rate limiting the caller.")
		rateLimitUnitTime    = fs.Duration("rate_limit_unit_time", 1*time.Minute, "The unit of time over which to measure the rate_limit_max_requests.")

		// Azure AD B2C
		azADTenantName = fs.String("azure_ad_tenant_name", "", "The name of the Azure AD tenant to sign users in against")
		azADUserFlow   = fs.String("azure_ad_user_flow", "", "The name of the user flow to log users in with")
		azADClientID   = fs.String("azure_ad_client_id", "", "The ID of the application/client users are signing in with")
		azADTenantID   = fs.String("azure_ad_tenant_id", "", "The ID of the tenant/directory to enroll users with")

		useLocalJWTs = fs.Bool("use_local_jwts", false, "If true, expect source JWTs to be self-signed, instead of from Azure B2C")

		// Private key for signing API keys that this service issues
		authPrivKeyFile = fs.String("auth_private_key_file", "", "The PEM-encoded PKCS #8 ASN.1 DER-formatted ED25519 private key")
		authPrivKeyID   = fs.String("auth_private_key_id", "", "A unique identifier for the private key.")

		allowedDomains     flagext.StringList
		allowedCORSOrigins flagext.StringList
		minLogLevel        zapcore.Level = zapcore.WarnLevel
	)
	fs.Var(&allowedDomains, "allowed_domains", "A comma-separated list of domains that are allowed to get valid credentials")
	fs.Var(&allowedCORSOrigins, "allowed_cors_origins", "A comma-separated list of CORS origins to allow traffic from")
	fs.Var(&minLogLevel, "min_log_level", "If set, retains logs at the given level and above. Options: 'debug', 'info', 'warn', 'error', 'dpanic', 'panic', 'fatal' - default warn.")

	// Allows for passing in configuration via a -config path/to/env-file.conf
	// flag, see https://pkg.go.dev/github.com/namsral/flag#readme-usage
	fs.String(flag.DefaultConfigFlagname, "", "path to config file")
	if err := fs.Parse(args[1:]); err != nil {
		return fmt.Errorf("failed to parse flags: %v", err)
	}

	reqFlags := []requiredFlag{
		{
			name: "env",
			val:  env,
		},
		{
			name: "auth_private_key_file",
			val:  authPrivKeyFile,
		},
		{
			name: "auth_private_key_id",
			val:  authPrivKeyID,
		},
	}
	if err := checkFlags(reqFlags); err != nil {
		return err
	}

	if *useLocalJWTs && *env != "local" {
		return fmt.Errorf("can only use local JWTs in a local environment, env was %q", *env)
	}

	if !*useLocalJWTs {
		reqAZFlags := []requiredFlag{
			{
				name: "azure_ad_tenant_name",
				val:  azADTenantName,
			},
			{
				name: "azure_ad_user_flow",
				val:  azADUserFlow,
			},
			{
				name: "azure_ad_client_id",
				val:  azADClientID,
			},
			{
				name: "azure_ad_tenant_id",
				val:  azADTenantID,
			},
		}
		if err := checkFlags(reqAZFlags); err != nil {
			return err
		}
	}

	priv, err := keyutil.DecodeED25519PrivateKeyFromFile(*authPrivKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load signing private key: %w", err)
	}

	userSwagger, err := user.GetSwagger()
	if err != nil {
		return fmt.Errorf("failed to load User swagger spec: %w", err)
	}

	testCredsSwagger, err := testcreds.GetSwagger()
	if err != nil {
		return fmt.Errorf("failed to load testcreds swagger spec: %w", err)
	}

	var logger *zap.Logger
	if *env == "local" {
		if logger, err = zap.NewDevelopment(); err != nil {
			return fmt.Errorf("failed to init logger: %w", err)
		}
	} else {
		if logger, err = zap.NewProduction(zap.AddStacktrace(zapcore.ErrorLevel)); err != nil {
			return fmt.Errorf("failed to init logger: %w", err)
		}
	}

	// Clear out the servers array in the swagger spec, that skips validating
	// that server names match. We don't know how this thing will be run.
	userSwagger.Servers = nil
	testCredsSwagger.Servers = nil

	jwKey, err := jwk.FromRaw(priv)
	if err != nil {
		return fmt.Errorf("failed to make JWK key: %w", err)
	}
	jwKey.Set(jwk.KeyIDKey, *authPrivKeyID)

	userSrv := &usersrv.Server{
		Issuer: &usersrv.TokenIssuer{
			Key: jwKey,
			Now: time.Now,
		},
		Logger: logger,
		Now:    func() time.Time { return time.Now().UTC() },
	}
	testCredsSrv := &testcredsrv.Server{
		Now:     func() time.Time { return time.Now().UTC() },
		JWTAuth: jwtauth.New("EdDSA", nil, priv.Public()),
	}

	userStrictHandler := user.NewStrictHandlerWithOptions(userSrv, nil /* middleware */, user.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  requestErrorHandlerFuncForService(logger, "user"),
		ResponseErrorHandlerFunc: responseErrorHandlerFuncForService(logger, "user"),
	})
	testCredsStrictHandler := testcreds.NewStrictHandlerWithOptions(testCredsSrv, nil /* middleware */, testcreds.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  requestErrorHandlerFuncForService(logger, "testcreds"),
		ResponseErrorHandlerFunc: responseErrorHandlerFuncForService(logger, "testcreds"),
	})

	r := chi.NewRouter()

	type middleware func(http.Handler) http.Handler

	routerWithMiddleware := func(addlMiddleware ...func(http.Handler) http.Handler) chi.Router {
		m := []func(http.Handler) http.Handler{
			// The order of these is important. We run RequestID and RealIP first to
			// populate relevant metadata for logging, and we run recovery immediately after
			// logging so it can catch any subsequent panics, but still has access to the
			// LogEntry created by the logging middleware.
			chimiddleware.RequestID,
			chimiddleware.RealIP,
			zaphttplog.NewMiddleware(logger),
			chimiddleware.Recoverer,
		}

		m = append(m, addlMiddleware...)
		return r.With(m...)
	}

	var authenticator, verifier func(http.Handler) http.Handler
	if *useLocalJWTs {
		logger.Info("Using local JWTs for source auth, see //cmd/tools/genjwt for more info")
		localAuth := localjwt.NewAuth(jwtauth.New("EdDSA", priv, priv.Public()), logger)
		authenticator, verifier = localAuth.Authenticator, localAuth.Verifier
	} else {
		logger.Info("Using Azure AD for source auth",
			zap.String("tenant_id", *azADTenantID),
			zap.String("tenant_name", *azADTenantName),
			zap.String("user_flow", *azADUserFlow),
			zap.String("client_id", *azADClientID),
		)
		// Accept Microsoft-issued JWTs
		azJWTAuth, err := azjwt.NewAuth(ctx, &azjwt.Config{
			Logger:    logger,
			Allowlist: allowlist.NewChecker(allowedDomains),
			Tenant:    *azADTenantName,
			TenantID:  *azADTenantID,
			Policy:    *azADUserFlow,
			ClientID:  *azADClientID,
		})
		if err != nil {
			return fmt.Errorf("failed to init Azure JWT client: %w", err)
		}
		authenticator, verifier = azJWTAuth.Authenticator, azJWTAuth.Verifier
	}

	user.HandlerWithOptions(userStrictHandler, user.ChiServerOptions{
		BaseRouter: routerWithMiddleware(
			verifier,
			authenticator,
			// Use our validation middleware to check all requests against the OpenAPI
			// schema. We do this after the logging stuff so we have info about
			// failed/malformed requests.
			oapimiddleware.OapiRequestValidatorWithOptions(userSwagger, &oapimiddleware.Options{
				Options: openapi3filter.Options{
					AuthenticationFunc: func(ctx context.Context, in *openapi3filter.AuthenticationInput) error {
						// We handle authentication with the verifier + authenticator above, though we
						// might eventually migrate those here.
						return nil
					},
				},
			}),
			rateLimitMiddleware(*rateLimitMaxRequests, *rateLimitUnitTime, logger),
		),
		ErrorHandlerFunc: errorHandlerFuncForService(logger, "user"),
	})

	testcreds.HandlerWithOptions(testCredsStrictHandler, testcreds.ChiServerOptions{
		BaseRouter: routerWithMiddleware(
			httpreq.Middleware,
			// We don't handle auth as middleware in the credential test service, because
			// we don't want to fail requests with invalid/missing tokens, we want to return
			// specific errors. So we handle it in /cmd/server/testcredsrv instead.

			// jwtauth.Verifier(testJWTAuth),
			// jwtauth.Authenticator,

			// Use our validation middleware to check all requests against the OpenAPI
			// schema. We do this after the logging stuff so we have info about
			// failed/malformed requests.
			oapimiddleware.OapiRequestValidator(testCredsSwagger),
		),
		ErrorHandlerFunc: errorHandlerFuncForService(logger, "testcreds"),
	})

	// Created with https://textkool.com/en/ascii-art-generator?hl=default&vl=default&font=Pagga&text=SILICON%0AAPI%0ASTARTER
	fmt.Println()
	fmt.Println(`
         █▀▄░█▄█░▀█▀        
         █▀▄░█░█░░█░        
         ▀░▀░▀░▀░▀▀▀        
░█▀▀░█▀▄░█▀▀░█▀▄░█▀▀░█▀▄░█░█
░█░░░█▀▄░█▀▀░█░█░▀▀█░█▀▄░▀▄▀
░▀▀▀░▀░▀░▀▀▀░▀▀░░▀▀▀░▀░▀░░▀░`)
	fmt.Println()

	// If CORS was specified, wrap our handler in that.
	var handler http.Handler
	if len(allowedCORSOrigins) > 0 {
		handler = cors.New(cors.Options{
			AllowedOrigins:   allowedCORSOrigins,
			AllowCredentials: true,
			AllowedHeaders:   []string{"Authorization", "Content-Type"},
			Debug:            *env == "local",
		}).Handler(r)
	} else {
		handler = r
	}

	s := &http.Server{
		Handler: handler,
		Addr:    fmt.Sprintf(":%d", *port),
	}

	// And we serve HTTP until the world ends.
	if err := s.ListenAndServe(); err != nil {
		return fmt.Errorf("error running HTTP server: %w", err)
	}

	return nil
}

func rateLimitMiddleware(maxReq int, windowLength time.Duration, logger *zap.Logger) func(http.Handler) http.Handler {
	// This example uses an in-memory rate limiter for simplicity, an application
	// that will be running multiple API instances should likely use something like
	// https://github.com/go-chi/httprate-redis to account for traffic across the
	// fleet.
	return httprate.Limit(
		maxReq,
		windowLength,
		httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
			_, claims, err := jwtauth.FromContext(r.Context())
			if err != nil {
				logger.Warn("rate limiting unauthenticated user, falling back to IP", zap.String("request_path", r.URL.Path), zap.String("ip", r.RemoteAddr), zap.Error(err))
				return r.RemoteAddr, nil
			}
			id, err := findFirstInClaims(claims, "user_id", "sub")
			if err != nil {
				return "", fmt.Errorf("failed to load user identifier: %w", err)
			}
			return id, nil
		}))
}

func findFirstInClaims(claims map[string]any, keys ...string) (string, error) {
	for _, k := range keys {
		v, ok := claims[k]
		if !ok {
			continue
		}
		vStr, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("%q claim was of unexpected type %T, wanted a string", k, v)
		}
		return vStr, nil
	}

	return "", errors.New("no valid claim was found")
}

func requestErrorHandlerFuncForService(logger *zap.Logger, svc string) func(w http.ResponseWriter, r *http.Request, err error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		// We log these at WARN because in aggregate, they might indicate an issue with our request handling.
		logger.Warn("error while parsing request", zap.String("service", svc), zap.Error(err))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}
}

func responseErrorHandlerFuncForService(logger *zap.Logger, svc string) func(w http.ResponseWriter, r *http.Request, err error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("error while handling request", zap.String("service", svc), zap.Error(err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func errorHandlerFuncForService(logger *zap.Logger, svc string) func(w http.ResponseWriter, r *http.Request, err error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("error while handling service request", zap.String("service", svc), zap.Error(err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}
