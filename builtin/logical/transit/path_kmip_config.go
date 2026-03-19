// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const kmipConfigStoragePath = "config/kmip"

// kmipConfig holds the configuration for the KMIP server listener.
type kmipConfig struct {
	Enabled           bool   `json:"enabled"`
	ListenAddr        string `json:"listen_addr"`
	ServerCertPEM     string `json:"server_cert_pem"`
	ServerKeyPEM      string `json:"server_key_pem"`
	TLSCACertPEM      string `json:"tls_ca_cert_pem"`
	RequireClientCert bool   `json:"require_client_cert"`
}

func (b *backend) pathKmipConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config/kmip",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTransit,
		},

		Fields: map[string]*framework.FieldSchema{
			"enabled": {
				Type:        framework.TypeBool,
				Default:     false,
				Description: "Whether the KMIP server is enabled.",
			},
			"listen_addr": {
				Type:        framework.TypeString,
				Default:     "0.0.0.0:5696",
				Description: "TCP address the KMIP server will listen on (host:port).",
			},
			"server_cert_pem": {
				Type:        framework.TypeString,
				Description: "PEM-encoded TLS certificate for the KMIP server.",
			},
			"server_key_pem": {
				Type:        framework.TypeString,
				Description: "PEM-encoded private key for the KMIP server certificate.",
			},
			"tls_ca_cert_pem": {
				Type:        framework.TypeString,
				Description: "PEM-encoded CA certificate used to verify client certificates.",
			},
			"require_client_cert": {
				Type:        framework.TypeBool,
				Default:     true,
				Description: "Whether to require and verify client TLS certificates.",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathKmipConfigRead,
				Summary:  "Read the current KMIP server configuration.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "kmip-configuration",
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathKmipConfigWrite,
				Summary:  "Configure the KMIP server.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "configure",
					OperationSuffix: "kmip",
				},
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathKmipConfigWrite,
				Summary:  "Configure the KMIP server.",
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb:   "configure",
					OperationSuffix: "kmip",
				},
			},
		},

		HelpSynopsis:    pathKmipConfigHelpSyn,
		HelpDescription: pathKmipConfigHelpDesc,
	}
}

func (b *backend) pathKmipConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.getKmipConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil //nolint:nilnil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"enabled":             cfg.Enabled,
			"listen_addr":         cfg.ListenAddr,
			"server_cert_pem":     cfg.ServerCertPEM,
			"tls_ca_cert_pem":     cfg.TLSCACertPEM,
			"require_client_cert": cfg.RequireClientCert,
			// server_key_pem is intentionally omitted from read responses
		},
	}, nil
}

func (b *backend) pathKmipConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Load existing config to allow partial updates
	cfg, err := b.getKmipConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &kmipConfig{
			ListenAddr:        "0.0.0.0:5696",
			RequireClientCert: true,
		}
	}

	if v, ok := d.GetOk("enabled"); ok {
		cfg.Enabled = v.(bool)
	}
	if v, ok := d.GetOk("listen_addr"); ok {
		cfg.ListenAddr = v.(string)
	}
	if v, ok := d.GetOk("server_cert_pem"); ok {
		cfg.ServerCertPEM = v.(string)
	}
	if v, ok := d.GetOk("server_key_pem"); ok {
		cfg.ServerKeyPEM = v.(string)
	}
	if v, ok := d.GetOk("tls_ca_cert_pem"); ok {
		cfg.TLSCACertPEM = v.(string)
	}
	if v, ok := d.GetOk("require_client_cert"); ok {
		cfg.RequireClientCert = v.(bool)
	}

	// Validate cert/key pair if both are provided
	if cfg.ServerCertPEM != "" && cfg.ServerKeyPEM != "" {
		if _, err := tls.X509KeyPair([]byte(cfg.ServerCertPEM), []byte(cfg.ServerKeyPEM)); err != nil {
			return logical.ErrorResponse("invalid server_cert_pem / server_key_pem: %s", err), logical.ErrInvalidRequest
		}
	} else if cfg.Enabled && (cfg.ServerCertPEM == "" || cfg.ServerKeyPEM == "") {
		return logical.ErrorResponse("server_cert_pem and server_key_pem are required when enabling the KMIP server"), logical.ErrInvalidRequest
	}

	// Validate CA cert PEM if provided
	if cfg.TLSCACertPEM != "" {
		if err := validateCACertPEM(cfg.TLSCACertPEM); err != nil {
			return logical.ErrorResponse("invalid tls_ca_cert_pem: %s", err), logical.ErrInvalidRequest
		}
	}

	entry, err := logical.StorageEntryJSON(kmipConfigStoragePath, cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// Restart KMIP server to pick up the new configuration.
	if err := b.restartKmipServer(cfg); err != nil {
		return logical.ErrorResponse("configuration saved, but failed to restart KMIP server: %s", err), nil
	}

	return nil, nil //nolint:nilnil
}

func (b *backend) getKmipConfig(ctx context.Context, s logical.Storage) (*kmipConfig, error) {
	entry, err := s.Get(ctx, kmipConfigStoragePath)
	if err != nil {
		return nil, fmt.Errorf("error reading KMIP config: %w", err)
	}
	if entry == nil {
		return nil, nil //nolint:nilnil
	}

	var cfg kmipConfig
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, fmt.Errorf("error decoding KMIP config: %w", err)
	}
	return &cfg, nil
}

// validateCACertPEM checks that the PEM string contains at least one valid X.509 certificate.
func validateCACertPEM(pemStr string) error {
	pool := x509.NewCertPool()
	rest := []byte(pemStr)
	found := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("invalid certificate block: %w", err)
		}
		pool.AppendCertsFromPEM([]byte(pemStr))
		found = true
	}
	if !found {
		return fmt.Errorf("no valid CERTIFICATE PEM block found")
	}
	return nil
}

const pathKmipConfigHelpSyn = `Configure the KMIP server for this transit mount`

const pathKmipConfigHelpDesc = `
This path configures the KMIP (Key Management Interoperability Protocol) server
that is embedded in this transit secrets engine mount. External KMIP clients
(databases, storage arrays, backup software) can connect to this server to
manage and use transit-managed cryptographic keys via the standard KMIP protocol.
`
