# hodei-authz-axum

Axum integration for the Hodei authorization framework.

## Two layers, one safe default

- **`authorize_with_state`** (new, `0.2.0`): verifies a bearer credential through
  a `PrincipalAuthenticator`, resolves an action/resource target, evaluates a
  real `Authorizer`, and forwards the request only on `Permit`.
- **`authorize_middleware`** (legacy, `0.1.1`): fail-closed with `403` and no
  handler execution when no authorizer is wired. Kept for compatibility; new
  routers should use `authorize_with_state`.

The middleware never treats `authorization`, `x-tenant-id` or any other
client-supplied header as an identity. Only a credential verified by the
configured authenticator becomes a `VerifiedPrincipal`.

## Usage

```rust
use std::sync::Arc;
use axum::{Extension, Router, middleware, routing::get};
use hodei_authz::VerifiedContext;
use hodei_authz_axum::{
    AuthorizeState, AuthorizationTarget, Target, TargetError, authorize_with_state,
};

let state = AuthorizeState::new(
    Arc::new(authenticator), // PrincipalAuthenticator
    Arc::new(authorizer),    // Authorizer (CedarAuthorizer in production)
    Arc::new(target),        // AuthorizationTarget: path/method -> ActionId + ResourceRef
);

let app = Router::new()
    .route("/repositories/{account}/{name}", get(handler))
    .layer(middleware::from_fn_with_state(state, authorize_with_state));

async fn handler(Extension(context): Extension<VerifiedContext>) -> String {
    context.account().to_string()
}
```

`AuthorizationTarget` maps the HTTP request to an `ActionId` and a `ResourceRef`.
It must be pure/deterministic and must not derive identity from headers. The
resolver can use the method, path and verified route parameters.

The default is **same-account only**: after authentication, a resource whose
account differs from the verified principal is denied before the authorizer.
For an explicit administrative flow, opt in with
`AuthorizeState::new(...).allow_cross_account(true)`. A permissive policy alone
does not open cross-account access.

### Layer ordering

The layer only covers routes registered **before** it in the same `Router`.
Attach it to a dedicated subrouter, or add it after every route, so a route
cannot be added later without the authorization layer:

```rust
let protected = Router::new()
    .route("/repositories/{account}/{name}", get(handler))
    .layer(middleware::from_fn_with_state(state, authorize_with_state));

let app = Router::new().route("/health", get(health)).merge(protected);
```

## Status contract

| Situation | Status | Handler |
| --- | --- | --- |
| Missing/empty/malformed credential | `401` | not executed |
| Authenticator rejects the credential | `401` | not executed |
| Target cannot be resolved | `400` | not executed |
| Cross-account target (default) | `403` | not executed |
| `AuthorizationOutcome::Deny` | `403` | not executed |
| `AuthorizationOutcome::Indeterminate` | `403` | not executed |
| `Permit` | downstream | executed with `VerifiedContext` extension |

The handler receives the per-request `VerifiedContext` extension. No mutable
authorization state is shared between requests; `AuthorizeState` is immutable
(`Arc` fields) and the context is built per request.

## Limit

The middleware does **not** replace use-case authorization when the decision
depends on resource state. Load the resource and re-check ownership/invariants
inside the use case when needed; the middleware authorizes the route target, not
a mutable aggregate.

## Legacy fail-closed layer

`authorize_middleware` still denies every request with `403` and never calls the
handler. It is retained so existing routers compile and remain closed until they
migrate to `authorize_with_state`. Do not remove the layer to make a `403`
disappear.

## Tests

```bash
cargo test -p hodei-authz-axum
```

`tests/middleware_authorization.rs` is an in-process Axum integration test:
missing/invalid/expired token → `401` without handler; permit → `200` with the
verified account; deny → `403`; cross-account → `403` even with a lax policy;
indeterminate → `403`; forged `x-tenant-id` does not replace the token identity;
malformed target → `400`; multi-thread concurrent requests keep independent
contexts.
`tests/middleware_fail_closed.rs` keeps the legacy fail-closed regressions.

## License

MIT OR Apache-2.0
