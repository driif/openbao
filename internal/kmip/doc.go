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
// Every operation runs as a request through the OpenBao HTTP handler with
// the client's token, certificates and address, so ACL policies, namespaces,
// audit, quotas and forwarding from standbys apply exactly as they do for an
// HTTP client. The auth mount's namespace is the part of auth_mount before
// its first "auth" segment; the transit mount is in that namespace too.
//
// A key's KMIP Unique Identifier is its transit name. Permissions are plain
// transit ACLs. With <mount> the transit mount, the operations need:
//
//	Operation        Method  Path                                    Capability
//	Create           POST    <mount>/keys/<name>                     update
//	Register         GET     <mount>/wrapping_key                    read
//	                 POST    <mount>/keys/<name>/import              update
//	Get              GET     <mount>/keys/<name>                     read
//	                 GET     <mount>/export/<type>/<name>/<version>  read
//	GetAttributes    GET     <mount>/keys/<name>                     read
//	Activate         GET     <mount>/keys/<name>                     read
//	Locate           GET     <mount>/keys/<name>                     read  (with an exact Name or UID)
//	                 LIST    <mount>/keys                            list  (otherwise, then a read per key)
//	Revoke           DELETE  <mount>/keys/<name>/soft-delete         delete
//	Destroy          DELETE  <mount>/keys/<name>                     delete
//	Encrypt          POST    <mount>/encrypt/<name>                  update
//	Decrypt          POST    <mount>/decrypt/<name>                  update
//	Sign             POST    <mount>/sign/<name>                     update
//	SignatureVerify  POST    <mount>/verify/<name>                   update
//	Query            answered by the listener
//	DiscoverVersions answered by the listener
//
// Get exports through encryption-key for AES and ChaCha20 keys, hmac-key for
// HMAC keys and signing-key for RSA and ECDSA keys. An RSA or ECDSA key that
// is not exportable answers Get with its public key, taken from the
// <mount>/keys/<name> read, so no export grant is involved.
//
// Revoke and Destroy both need delete, but on different paths: an exact
// grant on <mount>/keys/<name> allows Destroy and not Revoke. A glob such as
// <mount>/keys/app-* covers both. Destroy also needs the key's
// deletion_allowed set, which KMIP never sets.
//
// Grant update, not create, on <mount>/encrypt/*. Transit's encrypt endpoint
// creates a missing key for a caller that holds create, so that grant would
// let an Encrypt create keys outside Create.
//
// Create and Register make keys with exportable=true so Get can return their
// material. That cannot be undone in transit, which leaves the read grant on
// <mount>/export/* as the only guard on key material.
//
// Locate without an exact Name or UID lists the mount and reads every key,
// skipping those the client may not read. Each of those reads is audited and
// counts against quotas. A Locate read that is denied is not retried; any
// other request that gets a 403 logs in again and is retried once, because
// OpenBao answers an expired token and an ACL denial alike.
package kmip
