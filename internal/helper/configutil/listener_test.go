// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package configutil

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSingleIPTemplate(t *testing.T) {
	tests := []struct {
		name    string
		arg     string
		want    string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "test https addr",
			arg:     "https://vaultproject.io:8200",
			want:    "https://vaultproject.io:8200",
			wantErr: assert.NoError,
		},
		{
			name:    "test invalid template func",
			arg:     "{{FooBar}}",
			want:    "",
			wantErr: assert.Error,
		},
		{
			name:    "test partial template",
			arg:     "{{FooBar",
			want:    "{{FooBar",
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSingleIPTemplate(tt.arg)
			if !tt.wantErr(t, err, fmt.Sprintf("ParseSingleIPTemplate(%v)", tt.arg)) {
				return
			}

			assert.Equalf(t, tt.want, got, "ParseSingleIPTemplate(%v)", tt.arg)
		})
	}
}

func TestParseListeners_KMIP(t *testing.T) {
	kmipListener := func(settings string) string {
		return `
listener "kmip" {
  tls_cert_file      = "server.pem"
  tls_key_file       = "server.key"
  tls_client_ca_file = "ca.pem"
` + settings + `
}`
	}

	t.Run("accepted", func(t *testing.T) {
		config, err := ParseConfig(kmipListener(`
  address               = "127.0.0.1:5696"
  auth_mount            = "/tenant-a/auth/cert/"
  default_transit_mount = "transit/"`))
		require.NoError(t, err)
		require.Len(t, config.Listeners, 1)

		l := config.Listeners[0]
		assert.Equal(t, "kmip", l.Type)
		assert.Equal(t, "tenant-a/auth/cert", l.AuthMount)
		assert.Equal(t, "transit", l.DefaultTransitMount)
	})

	t.Run("accepted without default transit mount", func(t *testing.T) {
		config, err := ParseConfig(kmipListener(`auth_mount = "auth/cert"`))
		require.NoError(t, err)
		require.Len(t, config.Listeners, 1)
		assert.Equal(t, "auth/cert", config.Listeners[0].AuthMount)
		assert.Empty(t, config.Listeners[0].DefaultTransitMount)
	})

	rejected := map[string]struct {
		config string
		err    string
	}{
		"missing auth_mount": {
			config: kmipListener(""),
			err:    "kmip listener requires auth_mount",
		},
		"auth_mount outside auth": {
			config: kmipListener(`auth_mount = "cert"`),
			err:    "must name a mount under auth/",
		},
		"auth_mount without a mount": {
			config: kmipListener(`auth_mount = "ns1/auth"`),
			err:    "must name a mount under auth/",
		},
		"tls_disable": {
			config: kmipListener(`
  auth_mount  = "auth/cert"
  tls_disable = true`),
			err: "cannot set tls_disable",
		},
		"tls_disable_client_certs": {
			config: kmipListener(`
  auth_mount               = "auth/cert"
  tls_disable_client_certs = true`),
			err: "cannot set tls_disable_client_certs",
		},
		"cluster_address": {
			config: kmipListener(`
  auth_mount      = "auth/cert"
  cluster_address = "127.0.0.1:8201"`),
			err: "cannot set cluster_address",
		},
		"acme": {
			config: kmipListener(`
  auth_mount       = "auth/cert"
  tls_acme_domains = ["kmip.example.com"]`),
			err: "cannot use tls_acme_* settings",
		},
		"missing tls_client_ca_file": {
			config: `
listener "kmip" {
  tls_cert_file = "server.pem"
  tls_key_file  = "server.key"
  auth_mount    = "auth/cert"
}`,
			err: "kmip listener requires tls_client_ca_file",
		},
		"missing tls_cert_file": {
			config: `
listener "kmip" {
  tls_key_file       = "server.key"
  tls_client_ca_file = "ca.pem"
  auth_mount         = "auth/cert"
}`,
			err: "kmip listener requires tls_cert_file and tls_key_file",
		},
		"missing tls_key_file": {
			config: `
listener "kmip" {
  tls_cert_file      = "server.pem"
  tls_client_ca_file = "ca.pem"
  auth_mount         = "auth/cert"
}`,
			err: "kmip listener requires tls_cert_file and tls_key_file",
		},
		"auth_mount on tcp": {
			config: `
listener "tcp" {
  address    = "127.0.0.1:8200"
  auth_mount = "auth/cert"
}`,
			err: "only valid on kmip listeners",
		},
		"default_transit_mount on tcp": {
			config: `
listener "tcp" {
  address               = "127.0.0.1:8200"
  default_transit_mount = "transit"
}`,
			err: "only valid on kmip listeners",
		},
	}

	for name, tc := range rejected {
		t.Run(name, func(t *testing.T) {
			_, err := ParseConfig(tc.config)
			require.ErrorContains(t, err, tc.err)
		})
	}
}
