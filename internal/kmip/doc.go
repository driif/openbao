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
// A KMIP managed object is a transit key plus the kmip scope of the key's
// metadata record, <mount>/keys/<name>/metadata. The transit key holds the
// material, type, versions and lifecycle; the record holds only what
// transit cannot: stored attributes, Link attributes, and the Name of the
// object across ReKey. A key's KMIP Unique Identifier is its transit name.
// Permissions are plain transit ACLs. With <mount> the transit mount, the
// operations need:
//
//	Operation        Method  Path                                    Capability
//	Create           POST    <mount>/keys/<name>                     update
//	Register         GET     <mount>/wrapping_key                    read
//	                 POST    <mount>/keys/<name>/import              update
//	Get              GET     <mount>/keys/<name>                     read
//	                 GET     <mount>/export/<type>/<name>/<version>  read
//	GetAttributes    GET     <mount>/keys/<name>                     read
//	GetAttributeList GET     <mount>/keys/<name>                     read
//	AddAttribute     GET     <mount>/keys/<name>                     read
//	                 GET     <mount>/keys/<predecessor>              read  (a <name>.<n> with no ReKey record only)
//	                 POST    <mount>/keys/<name>/metadata            update
//	ReKey            GET     <mount>/keys/<name>                     read  (the key, its successor and the anchor)
//	                 POST    <mount>/keys/<name>                     update (the successor)
//	                 POST    <mount>/keys/<name>/metadata            update (key, successor and anchor)
//	                 DELETE  <mount>/keys/<name>/soft-delete         delete (retention, best effort)
//	Activate         GET     <mount>/keys/<name>                     read
//	Locate           GET     <mount>/keys/<name>                     read  (with an exact Name or UID)
//	                 GET     <mount>/keys/<name>.<n>                 read  (exact Name, after a ReKey)
//	                 LIST    <mount>/keys                            list  (otherwise, then a read per key)
//	Revoke           DELETE  <mount>/keys/<name>/soft-delete         delete
//	Destroy          GET     <mount>/keys/<name>                     read  (anchor check, skipped if denied)
//	                 GET     <mount>/keys/<name>.<n>                 read  (anchor of a rekeyed Name only)
//	                 DELETE  <mount>/keys/<name>                     delete
//	Encrypt          POST    <mount>/encrypt/<name>                  update
//	Decrypt          POST    <mount>/decrypt/<name>                  update
//	Sign             POST    <mount>/sign/<name>                     update
//	SignatureVerify  POST    <mount>/verify/<name>                   update
//	Query            answered by the listener
//	DiscoverVersions answered by the listener
//
// ReKey works on the key, its successor <name>.<n> and the Name's first
// generation, so it needs a glob such as <mount>/keys/app-* that covers
// <name>, <name>.<n> and their /metadata and /soft-delete paths. An exact
// grant on <mount>/keys/<name> is not enough. The same holds for Locate by
// Name once the Name was rekeyed: it reads the anchor <name>, then the
// current generation <name>.<n>. A role with only an exact grant gets an
// empty Locate, not an error, because a denied Locate read counts as no
// match.
//
// Attributes fall in three classes. Derived attributes come from the
// transit key: Unique Identifier, Object Type, Cryptographic Algorithm,
// Cryptographic Length, State and Initial Date. AddAttribute refuses them
// with Permission Denied. Name is honoured: it is the UID of the object's
// first generation and moves with ReKey. AddAttribute accepts only the
// object's Name already; renaming fails with Invalid Field. Every other
// attribute, standard or custom, is stored: kept verbatim as TTLV,
// returned by GetAttributes and GetAttributeList, matched by Locate, and
// inert. A stored Cryptographic Usage Mask does not restrict Encrypt,
// Decrypt, Sign or SignatureVerify, which read neither the key nor its
// record, and a stored Deactivation Date does not change State. Activation
// Date is the key's creation time unless the client stored one. Transit
// bounds the record: 64 KiB in total, 128 entries per scope, 8 KiB per
// value. A write over a bound fails with Invalid Field.
//
// ReKey replaces a symmetric key with a new transit key. The first
// generation of a Name is the anchor, with UID <name>; later generations
// are <name>.2, <name>.3 and so on, so Create and Register refuse a Name
// that ends in '.' and digits. The anchor's record names the current
// generation, so Locate by exact Name costs two reads however often the
// Name was rekeyed. The replacement gets the Name, the stored attributes,
// including Activation Date and Deactivation Date, and a Replaced Object
// Link; the predecessor gets a Replacement Object Link, loses its Name,
// and reports State Deactivated. It is not soft-deleted, so Get still
// returns its material. ReKey sets the ID Placeholder to the replacement.
// It refuses an Offset, a key it already replaced, and a template that
// changes the Name, algorithm, length or object type, or that carries any
// other derived attribute, even one equal to the predecessor's.
//
// ReKey commits by claiming the Name for the replacement on the anchor,
// expecting the predecessor, so two ReKeys of one Name cannot both win and
// the Name never moves back. Every step before and after is safe to repeat,
// so a client that retries an interrupted ReKey completes it. Before
// creating the successor, ReKey marks it as pending_successor in the
// predecessor's record and clears the marker once the successor's record
// is written; a retry that finds the successor without a record adopts it
// only while the marker names it. A successor's record is written once: a
// retry or a concurrent ReKey that finds it keeps it, so attributes added
// to the successor since stay. A retry that finds the Name already moved
// past the successor links the predecessor and leaves the Name where it
// is. A concurrent ReKey of the same key that finds the successor before
// its record reads both keys again, then adopts or resumes it. Any other
// existing key with the successor's UID fails the ReKey and names that key:
// retry, and if the error repeats, rename or delete it. One race
// remains: an operator who creates exactly that key between the marker
// write and the create gets it adopted.
// AddAttribute refuses a replacement that a ReKey created and has not yet
// recorded, which it tells by the predecessor's pending_successor. To check,
// it reads the predecessor of a <name>.<n> key that has no ReKey record.
// ReKey never relies on the "already existed" warning of a transit create,
// which transit does not send today.
//
// The cert role's kmip_rekey_retain, default 2, is how many generations
// stay readable, the current one included. After the commit, ReKey
// soft-deletes older generations, oldest first. The anchor keeps its
// record when its material goes, so the Name still resolves. The sweep is
// best effort: if a soft-delete fails, typically because the policy grants
// no delete on <mount>/keys/<name>/soft-delete, ReKey still succeeds, logs
// a warning naming the path and capability, and the next ReKey of the Name
// tries again.
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
// Destroy refuses the first generation of a rekeyed Name while the
// generation the Name points at still exists: that key holds the record that
// resolves the Name, and deleting it would lose the Name. Destroy the later
// generations first; the first generation can then be destroyed. The check
// reads the key and, for a rekeyed Name, the generation it points at. A role
// that may delete the key but not read it skips the check; one that may read
// the key but not that generation fails the Destroy. Both reads go through
// the usual retry, so a denied read costs a login, which keeps an expired
// token from skipping the check.
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
// skipping those the client may not read: it costs O(n) reads in the keys
// of the mount, and there is no attribute index. Each of those reads is
// audited and counts against quotas. A Locate read that is denied is not
// retried; any other request that gets a 403 logs in again and is retried
// once, because OpenBao answers an expired token and an ACL denial alike.
//
// A build with the kmipdump tag writes every request and response message,
// TTLV encoded, to the directory named by BAO_KMIP_TTLV_DUMP. The files
// hold key material in the clear. The replay test feeds such recordings
// from testdata/<client>/ to a listener.
//
// The dump runs as middleware, after kmip-go has decoded a request, and
// writes it encoded again by kmip-go. A recording therefore shows what the
// server understood in kmip-go's own encoding, not the client's bytes: a
// client encoding that kmip-go reads leniently is normalised away, and a
// request kmip-go cannot decode is answered InvalidMessage and never
// recorded. To capture a client's exact bytes, record below the decoder,
// for example with a TLS-terminating proxy.
package kmip
