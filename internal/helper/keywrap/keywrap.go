// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

// Package keywrap wraps key material for transit's BYOK import endpoints.
package keywrap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/kwp/subtle"
)

// Wrap wraps key for transit's import endpoints. A fresh AES-256 key wraps
// key with KWP, and wrappingKey encrypts that AES key with RSA-OAEP over
// SHA-256. The result is the OAEP ciphertext followed by the KWP ciphertext,
// which transit expects base64-encoded in its ciphertext field.
func Wrap(wrappingKey *rsa.PublicKey, key []byte) ([]byte, error) {
	ephemeralAESKey := make([]byte, 32)
	if _, err := rand.Read(ephemeralAESKey); err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	wrapKWP, err := subtle.NewKWP(ephemeralAESKey)
	if err != nil {
		return nil, fmt.Errorf("failure building key wrapping key: %w", err)
	}
	wrappedTargetKey, err := wrapKWP.Wrap(key)
	if err != nil {
		return nil, fmt.Errorf("failure wrapping source key: %w", err)
	}

	wrappedAESKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		wrappingKey,
		ephemeralAESKey,
		[]byte{},
	)
	if err != nil {
		return nil, fmt.Errorf("failure encrypting wrapped key: %w", err)
	}

	return append(wrappedAESKey, wrappedTargetKey...), nil
}
