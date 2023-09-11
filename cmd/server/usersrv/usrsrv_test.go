package usersrv

import (
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"math/rand"
	"testing"
	"time"

	"github.com/RMI/credential-service/emailctx"
	"github.com/RMI/credential-service/keyutil"
	"github.com/RMI/credential-service/openapi/user"
	"github.com/go-chi/jwtauth/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.uber.org/zap/zaptest"
)

const (
	TestPrivateKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOLQxXH9o3GaZXNIAvCFNtnqWBQPPn//nocVE3gp/WQJ
-----END PRIVATE KEY-----`
)

func TestLogin(t *testing.T) {
	srv, env := setup(t)
	uuid.SetRand(rand.New(rand.NewSource(0)))

	ctx := context.Background()
	tkn := jwt.New()
	tkn.Set("sub", "user123")
	tkn.Set("exp", env.curTime.Add(24*time.Hour))
	emails := []string{"test@allowed.example.com"}
	tkn.Set("emails", emails)
	ctx = jwtauth.NewContext(ctx, tkn, nil)
	ctx = emailctx.AddEmailsToContext(ctx, emails)

	got, err := srv.Login(ctx, user.LoginRequestObject{})
	if err != nil {
		t.Fatalf("srv.Login: %v", err)
	}

	want := user.Login200Response{
		Headers: user.Login200ResponseHeaders{
			SetCookie: "jwt=eyJhbGciOiJFZERTQSIsImtpZCI6InRlc3Qta2V5LWlkIiwidHlwIjoiSldUIn0.eyJhdWQiOlsicm1pLm9yZyJdLCJlbWFpbHMiOlsidGVzdEBhbGxvd2VkLmV4YW1wbGUuY29tIl0sImV4cCI6MTIzNTQzMTg4LCJpYXQiOjEyMzQ1Njc4OSwianRpIjoiMDE5NGZkYzItZmEyZi00Y2MwLTgxZDMtZmYxMjA0NWI3M2M4IiwibmJmIjoxMjM0NTY3MjksInN1YiI6InVzZXIxMjMifQ.aJFKyWQ2035ziql5GxjtN6kn4bqc2w-q4_C_EH4cKAkFuybh3zDGf8TS-kC_w0NUL-y3U5xgJ_xdEJWqLEz0Ag; Path=/; Expires=Fri, 30 Nov 1973 21:33:08 GMT; HttpOnly; Secure; SameSite=Lax",
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("unexpected login response (-want +got)\n%s", diff)
	}
}

func TestCreateAPIKey(t *testing.T) {
	srv, env := setup(t)

	ctx := context.Background()
	exp := env.curTime.Add(24 * time.Hour)
	tkn := jwt.New()
	tkn.Set("sub", "user123")
	tkn.Set("emails", []any{"test@allowed.example.com"})
	tkn.Set("exp", exp)
	ctx = jwtauth.NewContext(ctx, tkn, nil)

	got, err := srv.CreateAPIKey(ctx, user.CreateAPIKeyRequestObject{})
	if err != nil {
		t.Fatalf("srv.CreateAPIKey: %v", err)
	}

	want := user.CreateAPIKey200JSONResponse{
		Id:        "6e4ff95f-f662-45ee-a82a-bdf44a2d0b75",
		ExpiresAt: &exp,
		Key:       "eyJhbGciOiJFZERTQSIsImtpZCI6InRlc3Qta2V5LWlkIiwidHlwIjoiSldUIn0.eyJhdWQiOlsicm1pLm9yZyJdLCJleHAiOjEyMzU0MzE4OCwiaWF0IjoxMjM0NTY3ODksImp0aSI6IjZlNGZmOTVmLWY2NjItNDVlZS1hODJhLWJkZjQ0YTJkMGI3NSIsIm5iZiI6MTIzNDU2NzI5LCJzdWIiOiJ1c2VyMTIzIn0.2Xq5HOV9QYvSgI534oCPYzBvRH74f2Uek7tS04aXQ7YTUR_TKeyJkRyVp2AT3KfPh-aW38Lw-HAu3cR5cMAiBg",
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("unexpected login response (-want +got)\n%s", diff)
	}
}

func TestLogout(t *testing.T) {
	srv, _ := setup(t)

	ctx := context.Background()
	tkn := jwt.New()
	tkn.Set("sub", "user123")
	ctx = jwtauth.NewContext(ctx, tkn, nil)

	got, err := srv.Logout(ctx, user.LogoutRequestObject{})
	if err != nil {
		t.Fatalf("srv.Logout: %v", err)
	}

	want := user.Logout200Response{
		Headers: user.Logout200ResponseHeaders{
			SetCookie: "jwt=; Path=/; Expires=Wed, 28 Nov 1973 21:33:09 GMT; HttpOnly; Secure; SameSite=Lax",
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("unexpected login response (-want +got)\n%s", diff)
	}
}

type testEnv struct {
	curTime *time.Time
}

func setup(t *testing.T) (*Server, *testEnv) {
	priv := loadKey(t)

	jwKey, err := jwk.FromRaw(priv)
	if err != nil {
		t.Fatalf("failed to make JWK key: %v", err)
	}
	jwKey.Set(jwk.KeyIDKey, "test-key-id")

	curTime := time.Unix(123456788, 0)
	now := func() time.Time {
		curTime = curTime.Add(time.Second)
		return curTime
	}
	srv := &Server{
		Issuer: &TokenIssuer{
			Key: jwKey,
			Now: now,
		},
		Logger: zaptest.NewLogger(t),
		Now:    now,
	}

	return srv, &testEnv{curTime: &curTime}
}

func loadKey(t *testing.T) ed25519.PrivateKey {
	privDER := decodePEM(t, "PRIVATE KEY", []byte(TestPrivateKey))

	priv, err := keyutil.DecodeED25519PrivateKey(privDER)
	if err != nil {
		t.Fatalf("failed to decode private key: %v", err)
	}

	return priv
}

func decodePEM(t *testing.T, typ string, dat []byte) []byte {
	block, _ := pem.Decode(dat)
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}
	if block.Type != typ {
		t.Fatalf("block type was %q, expected %q", block.Type, typ)
	}

	return block.Bytes
}
