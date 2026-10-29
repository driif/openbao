// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

import (
	"encoding/json"
	"encoding/pem"
	"strconv"
	"time"

	kmiplib "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/ttlv"
)

// transitKeyType maps a KMIP algorithm and length to the transit key type
// that Create and Register ask for. keySize is the HMAC key size in bytes and
// zero for every other type.
func transitKeyType(alg kmiplib.CryptographicAlgorithm, bitlen int32) (keyType string, keySize int, err error) {
	switch alg {
	case kmiplib.CryptographicAlgorithmAES:
		switch bitlen {
		case 128:
			return "aes128-gcm96", 0, nil
		case 256:
			return "aes256-gcm96", 0, nil
		}

	case kmiplib.CryptographicAlgorithmChaCha20,
		kmiplib.CryptographicAlgorithmChaCha20Poly1305:
		if bitlen == 256 {
			return "chacha20-poly1305", 0, nil
		}

	case kmiplib.CryptographicAlgorithmRSA:
		switch bitlen {
		case 2048:
			return "rsa-2048", 0, nil
		case 3072:
			return "rsa-3072", 0, nil
		case 4096:
			return "rsa-4096", 0, nil
		}

	case kmiplib.CryptographicAlgorithmECDSA,
		kmiplib.CryptographicAlgorithmEC:
		switch bitlen {
		case 256:
			return "ecdsa-p256", 0, nil
		case 384:
			return "ecdsa-p384", 0, nil
		case 521:
			return "ecdsa-p521", 0, nil
		}

	case kmiplib.CryptographicAlgorithmHMACSHA1,
		kmiplib.CryptographicAlgorithmHMACSHA224,
		kmiplib.CryptographicAlgorithmHMACSHA256,
		kmiplib.CryptographicAlgorithmHMACSHA384,
		kmiplib.CryptographicAlgorithmHMACSHA512:
		// transit HMAC accepts 256..4096 bits
		// see keysutil.HmacMinKeySize and keysutil.HmacMaxKeySize
		if bitlen >= 256 && bitlen <= 4096 && bitlen%8 == 0 {
			return "hmac", int(bitlen / 8), nil
		}
	}

	return "", 0, kmipserver.Errorf(
		kmiplib.ResultReasonFeatureNotSupported,
		"unsupported algorithm %s with length %d", ttlv.EnumStr(alg), bitlen,
	)
}

// keyInfo is the part of transit's READ keys/<name> reply that KMIP uses.
type keyInfo struct {
	Name                 string                     `json:"name"`
	Type                 string                     `json:"type"`
	LatestVersion        int                        `json:"latest_version"`
	MinDecryptionVersion int                        `json:"min_decryption_version"`
	Exportable           bool                       `json:"exportable"`
	SoftDeleted          bool                       `json:"soft_deleted"`
	KeySize              int                        `json:"key_size"`
	Keys                 map[string]json.RawMessage `json:"keys"`

	// Metadata is the key's metadata record, which transit includes in the
	// read when it is not empty: scope, then entry, then values.
	Metadata map[string]map[string][]string `json:"metadata"`
}

// entry returns the values of an entry in the kmip scope. ReKey's markers
// live there too, and none of them is an attribute.
func (k *keyInfo) entry(name string) []string {
	return k.Metadata[metadataScope][name]
}

// single returns the value of a single-valued entry in the kmip scope.
func (k *keyInfo) single(name string) string {
	if values := k.entry(name); len(values) == 1 {
		return values[0]
	}
	return ""
}

// replacement returns the UID of the object that ReKey replaced this one
// with, if any.
func (k *keyInfo) replacement() string {
	return k.single(linkEntry(kmiplib.LinkTypeReplacementObjectLink))
}

// kmipName returns the object's Name: the UID of its first generation. An
// object ReKey replaced has handed its Name on and has none.
func (k *keyInfo) kmipName(uid string) (string, bool) {
	if k.replacement() != "" {
		return "", false
	}
	if anchor := k.single(entryAnchor); anchor != "" {
		return anchor, true
	}
	return uid, true
}

// kmipAttrs returns the KMIP algorithm, length and object type of the key.
// Asymmetric keys are reported as their private key.
func (k *keyInfo) kmipAttrs() (kmiplib.CryptographicAlgorithm, int32, kmiplib.ObjectType, error) {
	switch k.Type {
	case "aes128-gcm96":
		return kmiplib.CryptographicAlgorithmAES, 128, kmiplib.ObjectTypeSymmetricKey, nil
	case "aes256-gcm96":
		return kmiplib.CryptographicAlgorithmAES, 256, kmiplib.ObjectTypeSymmetricKey, nil
	case "chacha20-poly1305":
		return kmiplib.CryptographicAlgorithmChaCha20Poly1305, 256, kmiplib.ObjectTypeSymmetricKey, nil
	case "hmac":
		// Transit HMAC is hash-agnostic. KMIP requires a specific variant.
		// Default to HMAC-SHA256.
		return kmiplib.CryptographicAlgorithmHMACSHA256, int32(k.KeySize * 8), kmiplib.ObjectTypeSymmetricKey, nil
	case "rsa-2048":
		return kmiplib.CryptographicAlgorithmRSA, 2048, kmiplib.ObjectTypePrivateKey, nil
	case "rsa-3072":
		return kmiplib.CryptographicAlgorithmRSA, 3072, kmiplib.ObjectTypePrivateKey, nil
	case "rsa-4096":
		return kmiplib.CryptographicAlgorithmRSA, 4096, kmiplib.ObjectTypePrivateKey, nil
	case "ecdsa-p256":
		return kmiplib.CryptographicAlgorithmECDSA, 256, kmiplib.ObjectTypePrivateKey, nil
	case "ecdsa-p384":
		return kmiplib.CryptographicAlgorithmECDSA, 384, kmiplib.ObjectTypePrivateKey, nil
	case "ecdsa-p521":
		return kmiplib.CryptographicAlgorithmECDSA, 521, kmiplib.ObjectTypePrivateKey, nil
	}
	// ed25519 has no algorithm in kmip-go, and KMIP defines no XChaCha20.
	return 0, 0, 0, kmipserver.Errorf(
		kmiplib.ResultReasonFeatureNotSupported,
		"transit key type %q has no KMIP representation", k.Type,
	)
}

// state reports a soft-deleted key, and a key ReKey replaced, as
// Deactivated; every other key is Active from the moment transit creates
// it. A replaced key keeps its material until retention soft-deletes it.
func (k *keyInfo) state() kmiplib.State {
	if k.SoftDeleted || k.replacement() != "" {
		return kmiplib.StateDeactivated
	}
	return kmiplib.StateActive
}

// createdAt returns when a key version was created. Transit reports it as
// Unix seconds for symmetric keys and as creation_time for asymmetric ones;
// HMAC keys list no versions.
func (k *keyInfo) createdAt(version int) (time.Time, bool) {
	raw, ok := k.Keys[strconv.Itoa(version)]
	if !ok {
		return time.Time{}, false
	}

	var secs int64
	if err := json.Unmarshal(raw, &secs); err == nil {
		return time.Unix(secs, 0), true
	}

	var asym struct {
		CreationTime time.Time `json:"creation_time"`
	}
	if err := json.Unmarshal(raw, &asym); err == nil && !asym.CreationTime.IsZero() {
		return asym.CreationTime, true
	}

	return time.Time{}, false
}

// exportSource names the transit export type and format that return the
// key's latest material in the shape KMIP Get hands out.
func (k *keyInfo) exportSource(objType kmiplib.ObjectType) (exportType, format string) {
	switch {
	case objType == kmiplib.ObjectTypePrivateKey:
		// der is PKCS#8 for both RSA and ECDSA keys.
		return "signing-key", "der"
	case k.Type == "hmac":
		return "hmac-key", "raw"
	default:
		return "encryption-key", "raw"
	}
}

// publicKey returns the public half of the latest version of an asymmetric
// key as an X.509 SubjectPublicKeyInfo, from the PEM that transit lists for
// each version.
func (k *keyInfo) publicKey(alg kmiplib.CryptographicAlgorithm, bitlen int32) (kmiplib.Object, error) {
	var ver struct {
		PublicKey string `json:"public_key"`
	}
	raw := k.Keys[strconv.Itoa(k.LatestVersion)]
	if err := json.Unmarshal(raw, &ver); err != nil || ver.PublicKey == "" {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonGeneralFailure,
			"transit returned no public key for version %d of %q", k.LatestVersion, k.Name,
		)
	}
	block, _ := pem.Decode([]byte(ver.PublicKey))
	if block == nil {
		return nil, kmipserver.Errorf(
			kmiplib.ResultReasonGeneralFailure,
			"transit returned a public key for %q that is not PEM", k.Name,
		)
	}

	material := block.Bytes
	return &kmiplib.PublicKey{
		KeyBlock: kmiplib.KeyBlock{
			KeyFormatType: kmiplib.KeyFormatTypeX_509,
			KeyValue: &kmiplib.KeyValue{
				Plain: &kmiplib.PlainKeyValue{
					KeyMaterial: kmiplib.KeyMaterial{Bytes: &material},
				},
			},
			CryptographicAlgorithm: alg,
			CryptographicLength:    bitlen,
		},
	}, nil
}

// kmipObject wraps exported key material: raw bytes for symmetric keys,
// PKCS#8 DER for private keys.
func kmipObject(objType kmiplib.ObjectType, alg kmiplib.CryptographicAlgorithm, bitlen int32, material []byte) kmiplib.Object {
	if objType == kmiplib.ObjectTypePrivateKey {
		return &kmiplib.PrivateKey{
			KeyBlock: kmiplib.KeyBlock{
				KeyFormatType: kmiplib.KeyFormatTypePKCS_8,
				KeyValue: &kmiplib.KeyValue{
					Plain: &kmiplib.PlainKeyValue{
						KeyMaterial: kmiplib.KeyMaterial{Bytes: &material},
					},
				},
				CryptographicAlgorithm: alg,
				CryptographicLength:    bitlen,
			},
		}
	}

	return &kmiplib.SymmetricKey{
		KeyBlock: kmiplib.KeyBlock{
			KeyFormatType: kmiplib.KeyFormatTypeRaw,
			KeyValue: &kmiplib.KeyValue{
				Plain: &kmiplib.PlainKeyValue{
					KeyMaterial: kmiplib.KeyMaterial{Bytes: &material},
				},
			},
			CryptographicAlgorithm: alg,
			CryptographicLength:    bitlen,
		},
	}
}
