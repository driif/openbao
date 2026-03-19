# Transit KMIP Server Integration

## Overview

Extend OpenBao's transit secrets engine to act as a KMIP (Key Management Interoperability Protocol) server. External KMIP clients (databases, storage arrays, backup software) connect via mTLS to a TLS listener spawned by the transit backend, using standard KMIP protocol to create, manage, and use transit-managed cryptographic keys.

The `ovh/kmip-go` library (already an indirect dependency via go-kms-wrapping) provides the server-side KMIP infrastructure: TLS connection handling, TTLV encoding/decoding, and a `BatchExecutor` router. We implement the `OperationHandler` interface for each KMIP operation and map it to transit's existing key operations.

## Context

- Files involved:
  - `builtin/logical/transit/backend.go` - add kmipServer field and lifecycle hooks
  - `builtin/logical/transit/path_kmip_config.go` - new: KMIP config path
  - `builtin/logical/transit/kmip_server.go` - new: KMIP server wrapper
  - `builtin/logical/transit/kmip_handlers.go` - new: KMIP operation to transit operation mapping
  - `builtin/logical/transit/kmip_auth.go` - new: client cert to role mapping / authorization
  - `builtin/logical/transit/path_kmip_role.go` - new: cert-to-policy role config
  - `go.mod` / `go.sum` - promote `ovh/kmip-go` from indirect to direct
- Related patterns:
  - `path_cache_config.go` / `path_config_keys.go` - pattern for transit config paths
  - `kmipserver.BatchExecutor` + `kmipserver.HandleFunc[Req, Resp]` - operation routing
  - `backend.configMutex` + `backend.lm` - existing mutex pattern for backend state
  - `command/server/listener_tcp.go` - TLS listener setup pattern
- Dependencies: `github.com/ovh/kmip-go v0.3.3` (already in module graph, needs direct import)

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- **CRITICAL: every task MUST include new/updated tests**
- **CRITICAL: all tests must pass before starting next task**

## Implementation Steps

### Task 1: KMIP Configuration Path

**Files:**
- Create: `builtin/logical/transit/path_kmip_config.go`
- Create: `builtin/logical/transit/path_kmip_config_test.go`
- Modify: `builtin/logical/transit/backend.go` (register path)

- [x] Define `kmipConfig` struct: `Enabled bool`, `ListenAddr string`, `ServerCertPEM string`, `ServerKeyPEM string`, `TLSCACertPEM string`, `RequireClientCert bool`
- [x] Implement `pathKmipConfig()` returning a `*framework.Path` at pattern `config/kmip`
- [x] Implement read handler: load from storage at `config/kmip`
- [x] Implement write handler: validate cert/key PEM, store to storage, restart KMIP server if running
- [x] Register `b.pathKmipConfig()` in `Backend()` path list
- [x] Write tests covering read/write/update of KMIP config
- [x] Run `go test ./builtin/logical/transit/...` - must pass

### Task 2: KMIP Role Path (Client Cert → Policy Mapping)

**Files:**
- Create: `builtin/logical/transit/path_kmip_role.go`
- Create: `builtin/logical/transit/path_kmip_role_test.go`
- Modify: `builtin/logical/transit/backend.go` (register path)

- [x] Define `kmipRole` struct: `CertSubjectDN string`, `AllowedOperations []string`, `AllowedKeyNames []string`
- [x] Implement `pathKmipRole()` at pattern `kmip/roles/{name}` supporting create/read/list/delete
- [x] Implement `pathKmipRoleList()` at `kmip/roles/` with list operation
- [x] Store roles at storage path `kmip/roles/<name>`
- [x] Register paths in `Backend()`
- [x] Write tests for role CRUD and listing
- [x] Run tests - must pass

### Task 3: KMIP Server Lifecycle

**Files:**
- Create: `builtin/logical/transit/kmip_server.go`
- Create: `builtin/logical/transit/kmip_server_test.go`
- Modify: `builtin/logical/transit/backend.go` (add `kmipServer` field, call start/stop)

- [x] Define `transitKmipServer` struct holding `*kmipserver.Server`, `net.Listener`, cancel func, and reference to `*backend`
- [x] Implement `newTransitKmipServer(cfg *kmipConfig, b *backend) (*transitKmipServer, error)`:
  - parse server cert/key PEM via `tls.X509KeyPair`
  - parse CA cert for client auth if `RequireClientCert` is set
  - build `tls.Config` with `ClientAuth: tls.RequireAndVerifyClientCert`
  - call `tls.Listen("tcp", cfg.ListenAddr, tlsCfg)` to create listener
  - create `kmipserver.BatchExecutor`, register operation handlers (stub initially)
  - return `kmipserver.NewServer(listener, executor)`
- [x] Implement `Start() error` - runs `srv.Serve()` in a goroutine
- [x] Implement `Stop() error` - calls `srv.Shutdown()`
- [x] Add `kmipServer *transitKmipServer` and `kmipMu sync.Mutex` fields to `backend` struct
- [x] In `backend.go` after `Setup()`, load KMIP config and start server if `Enabled`
- [x] In `backend.Cleanup()`, stop KMIP server if running
- [x] Handle config updates from write handler (stop old, start new)
- [x] Promote `github.com/ovh/kmip-go` to direct dependency in `go.mod`
- [x] Write tests: server starts/stops, handles TLS connections, rejects invalid certs
- [x] Run tests - must pass

### Task 4: KMIP Authentication Middleware

**Files:**
- Create: `builtin/logical/transit/kmip_auth.go`
- Create: `builtin/logical/transit/kmip_auth_test.go`

- [x] Implement `authMiddleware(b *backend) kmipserver.Middleware`:
  - extract `*tls.ConnectionState` from `kmipserver` connection context
  - extract peer certificate subject DN from `ConnectionState.PeerCertificates[0]`
  - load matching `kmipRole` from storage by subject DN
  - store role in context for downstream handlers
  - return `OperationNotAllowed` if no matching role found
- [x] Implement `authorizeOperation(ctx context.Context, op kmip.Operation, keyName string) error`:
  - read role from context
  - check op string against `AllowedOperations`
  - check key name against `AllowedKeyNames` (empty = all allowed)
- [x] Register middleware via `executor.Use(authMiddleware(b))` in `newTransitKmipServer`
- [x] Write tests for auth middleware (valid cert, unknown cert, restricted ops)
- [x] Run tests - must pass

### Task 5: KMIP Key Management Operation Handlers

**Files:**
- Create: `builtin/logical/transit/kmip_handlers.go`
- Create: `builtin/logical/transit/kmip_handlers_test.go`

- [x] Implement helper `callTransit(ctx context.Context, b *backend, storage logical.Storage, op logical.Operation, path string, data map[string]interface{}) (*logical.Response, error)` to invoke transit paths internally
- [x] Implement `handleCreate(ctx, req *payloads.CreateRequestPayload) (*payloads.CreateResponsePayload, error)`:
  - map `CryptographicAlgorithm` to transit key type (aes128-gcm96, aes256-gcm96, rsa-2048, etc.)
  - call transit `CreateKey` via internal request
  - return `UniqueIdentifier` = key name
- [x] Implement `handleGet(ctx, req *payloads.GetRequestPayload) (*payloads.GetResponsePayload, error)`:
  - call transit `ExportKey` to retrieve raw key material
  - return as KMIP `SymmetricKey` or `PrivateKey` object
- [x] Implement `handleGetAttributes(ctx, req) (resp, error)`:
  - call transit `ReadKey`, map policy fields to KMIP attributes (CryptographicLength, Algorithm, State, dates)
- [x] Implement `handleLocate(ctx, req) (resp, error)`:
  - call transit `ListKeys`, filter by attributes if specified in request
- [x] Implement `handleDestroy(ctx, req) (resp, error)`:
  - call transit soft-delete or `DeleteKey`
- [x] Implement `handleActivate(ctx, req) (resp, error)` - no-op for transit (keys auto-activate), return success
- [x] Implement `handleRevoke(ctx, req) (resp, error)` - call transit soft-delete
- [x] Implement `handleRegister(ctx, req) (resp, error)`:
  - extract key material from KMIP object
  - call transit `ImportKey`
- [x] Register all handlers in `BatchExecutor` in `newTransitKmipServer`
- [x] Write tests for each handler (mock the transit backend calls)
- [x] Run tests - must pass

### Task 6: KMIP Cryptographic Operation Handlers

**Files:**
- Modify: `builtin/logical/transit/kmip_handlers.go`
- Modify: `builtin/logical/transit/kmip_handlers_test.go`

- [x] Implement `handleEncrypt(ctx, req *payloads.EncryptRequestPayload) (*payloads.EncryptResponsePayload, error)`:
  - call transit `Encrypt` with plaintext from `Data`
  - return ciphertext as `Data`
- [x] Implement `handleDecrypt(ctx, req *payloads.DecryptRequestPayload) (*payloads.DecryptResponsePayload, error)`:
  - call transit `Decrypt` with ciphertext from `Data`
  - return plaintext as `Data`
- [x] Implement `handleSign(ctx, req *payloads.SignRequestPayload) (*payloads.SignResponsePayload, error)`:
  - call transit `Sign`
- [x] Implement `handleVerify(ctx, req *payloads.VerifyRequestPayload) (*payloads.VerifyResponsePayload, error)`:
  - call transit `Verify`
- [x] Implement `handleQuery(ctx, req) (resp, error)`:
  - return supported operations list, server info
- [x] Register crypto handlers in `BatchExecutor`
- [x] Write tests for encrypt/decrypt/sign/verify round-trips
- [x] Run tests - must pass

### Task 7: Integration Tests

**Files:**
- Create: `builtin/logical/transit/kmip_integration_test.go`

- [x] Write an end-to-end test that:
  - starts a transit backend with KMIP enabled on a random port
  - connects using `ovh/kmip-go`'s `kmipclient` package
  - exercises Create, GetAttributes, Locate, Encrypt, Decrypt, Destroy operations
  - verifies auth middleware rejects unauthenticated connections
- [x] Run full integration test: `go test -run TestKmip ./builtin/logical/transit/...`
- [x] Run full test suite: `go test ./builtin/logical/transit/...`
- [x] Run linter: `make lint` or `golangci-lint run ./builtin/logical/transit/...`

### Task 8: Verify acceptance criteria

- [x] Run full transit test suite: `go test ./builtin/logical/transit/...`
- [x] Run broader test suite: `go test ./...`
- [x] Run linter: check for any new lint errors in changed files
- [x] Verify KMIP server starts/stops cleanly with transit mount mount/unmount

### Task 9: Update documentation

- [x] Add KMIP server configuration docs to transit engine documentation
- [x] Document supported KMIP operations and version (1.2-1.4)
- [x] Document cert-to-role authentication model
- [x] Move this plan to `docs/plans/completed/`
