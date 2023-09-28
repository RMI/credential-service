// Package secrets validates and parses all sensitive configuration.
package secrets

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/RMI/credential-service/keyutil"
)

type Config struct {
	AuthSigningKey AuthSigningKey
	AzureAD        *AzureAD
}

type AuthSigningKey struct {
	ID         string
	PrivateKey ed25519.PrivateKey
}

type AzureAD struct {
	TenantName string
	UserFlow   string
	ClientID   string
	TenantID   string
}

type RawConfig struct {
	AuthSigningKey *RawAuthSigningKey
	AzureAD        *RawAzureAD
}

type RawAuthSigningKey struct {
	ID   string
	Data string
}

type RawAzureAD struct {
	TenantName string
	UserFlow   string
	ClientID   string
	TenantID   string
}

func Load(rawCfg *RawConfig) (*Config, error) {
	if rawCfg == nil {
		return nil, errors.New("no raw config provided")
	}

	authSigningKey, err := parseAuthSigningKey(rawCfg.AuthSigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse auth signing key config: %w", err)
	}

	azureAD, err := parseAzureAD(rawCfg.AzureAD)
	if err != nil {
		return nil, fmt.Errorf("failed to parse azure AD config: %w", err)
	}

	return &Config{
		AuthSigningKey: authSigningKey,
		AzureAD:        azureAD,
	}, nil
}

func parseAzureAD(az *RawAzureAD) (*AzureAD, error) {
	// Not required when --use_local_jwts is used
	if az == nil {
		return nil, nil
	}
	if az.TenantName == "" {
		return nil, errors.New("no tenant_name was provided")
	}
	if az.UserFlow == "" {
		return nil, errors.New("no user_flow was provided")
	}
	if az.ClientID == "" {
		return nil, errors.New("no client_id was provided")
	}
	if az.TenantID == "" {
		return nil, errors.New("no tenant_id was provided")
	}
	return &AzureAD{
		TenantName: az.TenantName,
		UserFlow:   az.UserFlow,
		ClientID:   az.ClientID,
		TenantID:   az.TenantID,
	}, nil
}

func parseAuthSigningKey(ask *RawAuthSigningKey) (AuthSigningKey, error) {
	if ask == nil {
		return AuthSigningKey{}, errors.New("no auth_private_key was provided")
	}

	if ask.ID == "" {
		return AuthSigningKey{}, errors.New("no auth_private_key.id was provided")
	}

	if ask.Data == "" {
		return AuthSigningKey{}, errors.New("no auth_private_key.data was provided, should be PEM-encoded PKCS #8 ASN.1 DER-formatted ED25519 private key")
	}

	priv, err := loadPrivateKey(ask.Data)
	if err != nil {
		return AuthSigningKey{}, fmt.Errorf("failed to load auth signing key: %w", err)
	}
	return AuthSigningKey{
		ID:         ask.ID,
		PrivateKey: priv,
	}, nil
}

func loadPrivateKey(in string) (ed25519.PrivateKey, error) {
	in = strings.ReplaceAll(in, `\n`, "\n")
	privDER, err := decodePEM("PRIVATE KEY", []byte(in))
	if err != nil {
		return nil, fmt.Errorf("failed to decode PEM-encoded public key: %w", err)
	}

	pub, err := keyutil.DecodeED25519PrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	return pub, nil
}

func decodePEM(typ string, dat []byte) ([]byte, error) {
	block, _ := pem.Decode(dat)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	if block.Type != typ {
		return nil, fmt.Errorf("block type was %q, expected %q", block.Type, typ)
	}

	return block.Bytes, nil
}
