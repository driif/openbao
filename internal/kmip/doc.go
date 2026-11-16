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
// quotas and forwarding from standbys apply as they do for an HTTP client.
// A core audit hook also records each KMIP operation and refusal without key
// material, linked to the transit audit records by server-generated request IDs.
// A standby without an audit broker refuses operations other than discovery. The auth mount's namespace is the part of auth_mount before
// its first "auth" segment; the transit mount is in that namespace too.
//
// A KMIP managed object is a transit key plus the kmip/ entries of the key's
// metadata record, <mount>/keys/<name>/metadata. The transit key holds the
// material, type, versions and soft-delete; the record holds only what
// transit cannot: stored attributes, Link attributes, the Name of the
// object across ReKey, and the compromise and destroy marks. A key's KMIP
// Unique Identifier is its transit name. Permissions are plain transit
// ACLs. With <mount> the transit mount, the operations need:
//
//	Operation        Method  Path                                    Capability
//	Create           GET     <mount>/keys/<name>                     read   (a template with stored attributes)
//	                 POST    <mount>/keys/<name>                     update
//	                 GET     <mount>/keys/<name>/metadata            read   (a template with stored attributes)
//	                 POST    <mount>/keys/<name>/metadata            update (a template with stored attributes)
//	                 DELETE  <mount>/keys/<name>/soft-delete         delete (only when that write fails, for a generated name)
//	Register         GET     <mount>/wrapping_key                    read
//	                 POST    <mount>/keys/<name>/import              update
//	                 GET     <mount>/keys/<name>/metadata            read   (a template with stored attributes)
//	                 POST    <mount>/keys/<name>/metadata            update (a template with stored attributes)
//	                 DELETE  <mount>/keys/<name>/soft-delete         delete (only when that write fails)
//	Get              GET     <mount>/keys/<name>                     read
//	                 GET     <mount>/export/<type>/<name>/<version>  read
//	GetAttributes    GET     <mount>/keys/<name>                     read
//	                 GET     <mount>/keys/<name>/metadata            read
//	GetAttributeList GET     <mount>/keys/<name>                     read
//	                 GET     <mount>/keys/<name>/metadata            read
//	AddAttribute     GET     <mount>/keys/<name>                     read
//	                 GET     <mount>/keys/<name>/metadata            read  (initial read and before the metadata write)
//	                 GET     <mount>/keys/<predecessor>              read  (a <name>.<n> with no ReKey record only)
//	                 GET     <mount>/keys/<predecessor>/metadata     read  (same optional predecessor check)
//	                 POST    <mount>/keys/<name>/metadata            update
//	ModifyAttribute  GET     <mount>/keys/<name>                     read
//	                 GET     <mount>/keys/<name>/metadata            read  (initial read and before the metadata write)
//	                 GET     <mount>/keys/<predecessor>              read  (a <name>.<n> with no ReKey record only)
//	                 GET     <mount>/keys/<predecessor>/metadata     read  (same optional predecessor check)
//	                 POST    <mount>/keys/<name>/metadata            update
//	DeleteAttribute  GET     <mount>/keys/<name>                     read
//	                 GET     <mount>/keys/<name>/metadata            read  (initial read and before the metadata write)
//	                 GET     <mount>/keys/<predecessor>              read  (a <name>.<n> with no ReKey record only)
//	                 GET     <mount>/keys/<predecessor>/metadata     read  (same optional predecessor check)
//	                 POST    <mount>/keys/<name>/metadata            update
//	ReKey            GET     <mount>/keys/<name>                     read  (the key, its successor and the anchor)
//	                 GET     <mount>/keys/<name>/metadata            read  (key, successor and anchor; before each metadata write)
//	                 POST    <mount>/keys/<name>                     update (the successor)
//	                 POST    <mount>/keys/<name>/metadata            update (key, successor and anchor)
//	                 DELETE  <mount>/keys/<name>/soft-delete         delete (retention, best effort)
//	Activate         GET     <mount>/keys/<name>                     read
//	                 GET     <mount>/keys/<name>/metadata            read  (initial read, and before the write)
//	                 POST    <mount>/keys/<name>/metadata            update (Pre-Active objects only)
//	Locate           GET     <mount>/keys/<name>                     read  (with an exact Name or UID)
//	                 GET     <mount>/keys/<name>/metadata            read  (Name, State or stored-attribute filters; anchor and current for Name)
//	                 GET     <mount>/keys/<name>.<n>                 read  (exact Name, after a ReKey)
//	                 LIST    <mount>/keys                            list  (otherwise, then a read per key)
//	Revoke           GET     <mount>/keys/<name>                     read
//	                 GET     <mount>/keys/<name>/metadata            read  (initial read and before the metadata write)
//	                 POST    <mount>/keys/<name>/metadata            update
//	                 DELETE  <mount>/keys/<name>/soft-delete         delete (a key not soft-deleted yet)
//	Destroy          GET     <mount>/keys/<name>                     read
//	                 GET     <mount>/keys/<name>/metadata            read  (initial read and before the metadata write)
//	                 DELETE  <mount>/keys/<name>/soft-delete         delete (a key not soft-deleted yet)
//	                 POST    <mount>/keys/<name>/metadata            update (not for a Destroyed object)
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
// Attributes fall in four classes. Derived attributes come from the
// transit key and the record: Unique Identifier, Object Type, Cryptographic
// Algorithm, Cryptographic Length, State and Initial Date. Server-set
// attributes are stored by Revoke and Destroy only: Compromise Date,
// Compromise Occurrence Date, Destroy Date and Revocation Reason.
// AddAttribute, ModifyAttribute and DeleteAttribute refuse both classes
// with Permission Denied, and so does a Create, Register or ReKey template.
// Name is honoured: it is the UID of the object's first generation and
// moves with ReKey. AddAttribute accepts only the object's Name already;
// renaming fails with Invalid Field, and so do ModifyAttribute and
// DeleteAttribute of Name. Every other attribute, standard or custom, is
// stored: kept verbatim as TTLV, returned by GetAttributes and
// GetAttributeList, and matched by Locate. A stored Cryptographic Usage
// Mask does not restrict Encrypt, Decrypt, Sign or SignatureVerify, which
// read neither the key nor its record. A stored Activation Date and
// Deactivation Date change the State that GetAttributes, GetAttributeList
// and Locate report, as below, and nothing else. Activation Date is the
// key's creation time unless the client stored one. Transit bounds the
// record: 64 KiB serialized, 1024 keys, 512 bytes per non-empty key, and
// 8 KiB per value. Each kmip/<entry> is a JSON array, so the 8 KiB limit
// applies to all instances of an attribute entry together. A write over a
// bound fails with Invalid Field. The adapter reads and replaces the record
// with POST and cas, preserving unrelated entries. It retries a CAS
// mismatch up to eight attempts, then returns General Failure asking for a
// retry. Every check of an operation that writes the record runs again on
// the record of each attempt. It never sends PATCH.
//
// ModifyAttribute and DeleteAttribute select an instance by Attribute
// Index, 0 when absent, as GetAttributes numbers them: the Links ReKey
// wrote come first and cannot be changed. ModifyAttribute of the Activation
// Date that no client stored stores the new value; DeleteAttribute of it
// finds nothing. A missing instance is Item Not Found, since KMIP 1.x has
// no Attribute Not Found. Both refuse a ReKey replacement that is still
// being created, as AddAttribute does.
//
// Create and Register store the stored attributes of their template, by
// the rules a ReKey template follows; a template with none sends no
// metadata request. If that write fails, transit has already made the key,
// and the operation fails with General Failure naming the key. Transit
// answers a create of an existing key with that key, so the listener
// soft-deletes the key, best effort, only when no other client can hold
// it: a Register, since transit's import refuses an existing key, and a
// Create without a Name, whose generated name is a fresh UUID. A Create
// with a Name leaves the key Active without its attributes, because another
// client can create the same Name between Create's read and its create and
// share the key. If the soft-delete fails, the key also stays Active, and
// the error says so. Create with stored attributes reads the key first and
// refuses one that exists, including one that transit reports soft-deleted,
// and a template write refuses a record that already holds KMIP entries. A
// retry with the same Name therefore fails, and an operator restores,
// purges or keeps the key.
//
// ReKey replaces a symmetric key with a new transit key. The first
// generation of a Name is the anchor, with UID <name>; later generations
// are <name>.2, <name>.3 and so on, so Create and Register refuse a Name
// that ends in '.' and digits. The anchor's record names the current
// generation, so Locate by exact Name reads at most two keys and their
// metadata when no ReKey moves it during the lookup. A concurrent ReKey
// can make Locate resolve the anchor again. The replacement gets the Name,
// the stored attributes,
// including Activation Date and Deactivation Date, and a Replaced Object
// Link; the predecessor gets a Replacement Object Link, loses its Name,
// and reports State Deactivated. It is not soft-deleted, so Get still
// returns its material. ReKey sets the ID Placeholder to the replacement.
// It refuses an Offset, a Compromised or Destroyed object, a key it already
// replaced, and a template that changes the Name, algorithm, length or
// object type, or that carries any other derived or server-set attribute,
// even one equal to the predecessor's. A replacement whose copied
// Deactivation Date is past reports Deactivated.
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
// The cert role's kmip_rekey_retain defaults to 0, which keeps every
// generation and sends no retention soft-delete. A positive value opts into
// the sweep and sets how many generations stay readable, the current one
// included. After the commit, an enabled sweep soft-deletes older
// generations, oldest first. The anchor keeps its record when its material
// goes, so the Name still resolves. The sweep is
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
// State is derived, in this order. The destroy mark gives Destroyed, or
// Destroyed Compromised with the compromise mark too. The compromise mark
// gives Compromised. A key that is soft-deleted, replaced by ReKey, or past
// a stored Deactivation Date is Deactivated. A key before a stored
// Activation Date is Pre-Active. Any other key is Active, so a new object is
// Active unless its template holds a future Activation Date. The marks are
// the kmip/compromised and kmip/destroyed entries of the record; they are
// not attributes, and no KMIP operation but Revoke and Destroy sets them. A
// refusal for the wrong State is Permission Denied, with a message that
// names the State, since KMIP 1.x has no Wrong Key Lifecycle State reason.
//
// Activate stores now as the Activation Date of a Pre-Active object, which
// makes it Active. Of an Active object, it succeeds and writes nothing; any
// other State is refused. A stored Activation Date or Deactivation Date
// that does not decode fails Activate with General Failure.
//
// Revoke with reason Key Compromise or CA Compromise sets the compromise
// mark, the Compromise Date (now) and the Compromise Occurrence Date: the
// request's, or else the Initial Date. A second compromise Revoke keeps
// the first dates. Any other reason sets the Deactivation Date to now,
// unless one at or before now is stored. Both store the Revocation Reason,
// then soft-delete the key, which transit then refuses for every
// cryptographic operation. Revoke refuses a Destroyed object, and a
// Revoke with any other reason refuses a Pre-Active or Compromised object,
// as KMIP 1.4 has no such transition. The record goes first: if the
// soft-delete fails, the object reports Compromised or Deactivated, and a
// retry of the Revoke soft-deletes the key and keeps the first dates.
//
// Destroy is soft. It refuses an Active object, and succeeds with no write
// on a Destroyed one. On a Pre-Active, Deactivated or Compromised object,
// it soft-deletes the key unless it is soft-deleted already, then sets the
// destroy mark and the Destroy Date. It never deletes the key, so
// deletion_allowed has no effect on it: purging a key is an operator
// action outside KMIP. The soft-delete goes first, so Get never returns
// material of an object that reports Destroyed; an interrupted Destroy
// leaves it Deactivated, and a retry finishes it. Get of a Destroyed
// object fails as for any soft-deleted key; GetAttributes still reports
// its State and dates. The record survives Destroy, so destroying the
// first generation of a rekeyed Name keeps the Name. To undo a Destroy,
// restore the key with transit's soft-delete-restore, then remove
// kmip/destroyed and kmip/attr/Destroy Date through the metadata path.
//
// Revoke and Destroy need read on <mount>/keys/<name>, read and update on
// its metadata, and delete on <mount>/keys/<name>/soft-delete; neither
// sends DELETE <mount>/keys/<name>. Denying delete on
// <mount>/keys/<name>/soft-delete denies Revoke and Destroy: each fails at
// the soft-delete, which Destroy skips only for a key soft-deleted already.
// Revoke has written the record by then, so the object reports Compromised
// or Deactivated while transit still serves the key. Activate needs read
// on the key's metadata, and update on it for a Pre-Active object.
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
// reading metadata for Name, State or stored-attribute filters, and skipping
// candidates whose key or metadata read is denied. It costs O(n) reads in
// the keys of the mount, and there is no attribute index. Each of those reads is
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
