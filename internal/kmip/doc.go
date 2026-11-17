// Copyright (c) The OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

// Package kmip serves KMIP on a kmip listener by turning each KMIP operation
// into ordinary OpenBao requests against a transit mount.
//
// A client authenticates with its TLS client certificate. On its first
// operation that needs OpenBao, a connection logs in through the listener's
// cert auth mount without a role name, so cert auth picks the role whose
// constraints match the certificate. The role's kmip_transit_mount, or else
// the listener's default_transit_mount, names the transit mount; its
// kmip_key_prefix names keys created or registered without a Name. The
// token lives as long as the connection: the session logs in again shortly
// before the TTL runs out, and revokes a service token it replaces or that
// is still live when the connection closes.
//
// Every operation runs as requests through the OpenBao HTTP handler with
// the client's token, certificates and address, so ACL policies, namespaces,
// quotas and forwarding from standbys apply as they do for an HTTP client.
// The auth mount's namespace is the part of auth_mount before its first
// "auth" segment; the transit mount is in that namespace too. A request
// that gets a 403 logs in again and is retried, once per operation, because
// OpenBao answers an expired token and an ACL denial alike. A denied read
// of a candidate in a Locate scan is not retried: it counts as no match.
//
// A core audit hook records each KMIP operation and refusal without key
// material, linked to the transit audit records by server-generated request
// IDs. A standby without an audit broker refuses operations other than
// Query and DiscoverVersions.
//
// A KMIP managed object is a transit key plus the kmip/ entries of the key's
// metadata record, <mount>/keys/<name>/metadata. The transit key holds the
// material, type, versions and soft-delete; the record holds only what
// transit cannot: stored attributes, Link attributes, the Name of the
// object across ReKey, and the compromise and destroy marks. A key's KMIP
// Unique Identifier is its transit name. The package reads the record and
// replaces it with POST and cas, preserving unrelated entries, and runs
// every check of a writing operation again on the record of each attempt.
//
// Unique Identifier, Object Type, Cryptographic Algorithm, Cryptographic
// Length, State and Initial Date are derived from the key and the record.
// Compromise Date, Compromise Occurrence Date, Destroy Date and Revocation
// Reason are set by Revoke and Destroy only. Name is the UID of the object's
// first generation and moves with ReKey. Every other attribute is stored
// verbatim as TTLV.
//
// Create and Register make keys with exportable=true so that Get can return
// their material. Transit cannot undo that, which leaves the read grant on
// <mount>/export/* as the only guard on key material.
//
// Revoke and Destroy soft-delete the transit key, and Destroy never purges
// it. Transit then refuses the key, so Get cannot return its material, and
// Locate leaves the object out unless the request names its State. A refusal
// for the wrong State is Permission Denied, since KMIP 1.x has no Wrong Key
// Lifecycle State reason.
//
// ReKey replaces a symmetric key with a new transit key. The first
// generation of a Name is the anchor, with UID <name>; later generations
// are <name>.2, <name>.3 and so on. The rekey function gives the steps.
//
// The requests and ACL capabilities of each operation, the lifecycle rules
// and the limits are in website/content/docs/configuration/listener/kmip.mdx.
//
// A build with the kmipdump tag writes every request and response message,
// TTLV encoded, to the directory named by BAO_KMIP_TTLV_DUMP. The files hold
// key material in the clear. The replay test feeds such recordings from
// testdata/<client>/ to a listener. The dump runs after kmip-go has decoded
// a request and writes it encoded again, so a recording shows what the
// server understood, not the client's bytes, and a request that kmip-go
// cannot decode is never recorded.
package kmip
