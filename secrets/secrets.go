// Package secrets implements a wrapper around sops
// (https://github.com/mozilla/sops) that decrypts encrypted secret files on
// disk.
package secrets

import (
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/RMI/credential-service/keyutil"
	"github.com/getsops/sops/v3/decrypt"
)

const (
	// sopsFileExtension is the suffix we expect all
	// sops-encrypted configurations to have.
	sopsFileExtension = ".enc.json"
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

type config struct {
	AuthSigningKey *authSigningKey `json:"auth_private_key"`
	AzureAD        *azureAD        `json:"azure_ad"`
}

type authSigningKey struct {
	ID   string `json:"id"`
	Data string `json:"data"`
}

type azureAD struct {
	TenantName string `json:"tenant_name"`
	UserFlow   string `json:"user_flow"`
	ClientID   string `json:"client_id"`
	TenantID   string `json:"tenant_id"`
}

func Load(name string) (*Config, error) {
	var cfg config
	if err := loadConfig(name, &cfg); err != nil {
		return nil, err
	}

	authSigningKey, err := parseAuthSigningKey(cfg.AuthSigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse auth signing key config: %w", err)
	}

	azureAD, err := parseAzureAD(cfg.AzureAD)
	if err != nil {
		return nil, fmt.Errorf("failed to parse azure AD config: %w", err)
	}

	return &Config{
		AuthSigningKey: authSigningKey,
		AzureAD:        azureAD,
	}, nil
}

func parseAzureAD(az *azureAD) (*AzureAD, error) {
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

func parseAuthSigningKey(ask *authSigningKey) (AuthSigningKey, error) {
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

func loadConfig(name string, v interface{}) error {
	if err := checkFilename(name); err != nil {
		return err
	}

	dat, err := decrypt.File(name, "json")
	if err != nil {
		return fmt.Errorf("failed to decrypt file: %w", err)
	}

	if err := json.Unmarshal(dat, v); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return nil
}

func checkFilename(name string) error {
	fn := filepath.Base(name)
	if !strings.HasSuffix(fn, sopsFileExtension) {
		return fmt.Errorf("the given sops config %q does not have the expected extension %q", fn, sopsFileExtension)
	}
	return nil
}

func loadPrivateKey(in string) (ed25519.PrivateKey, error) {
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
