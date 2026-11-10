# hodei-authz-axum

Axum integration for the Hodei authorization framework.

## Security status: fail-closed

> **Security correction.** `authorize_middleware` used to call
> `next.run(req)` unconditionally, so every route behind it was effectively
> public. Version `0.1.0` is affected. This source tree fixes it as `0.1.1`:
> the middleware denies every request that crosses the layer with
> `403 Forbidden` and never executes the handler, because the crate does not
> yet own a verified authorizer.
>
> The fix is **not published yet**. Until `0.1.1` is on crates.io, consume the
> Git revision or a local patch; do not install `0.1.0`.

The middleware is intentionally fail-closed until an authenticated authorizer
adapter is wired. Do **not** remove the layer to make a `403` disappear, and do
not treat the layer as a no-op.

## Installation

Once `0.1.1` is published (see the status above), install:

```toml
[dependencies]
hodei-authz-axum = "0.1.1"
axum = "0.8"
```

## Usage

```rust
use axum::{Router, middleware, routing::get};
use hodei_authz_axum::authorize_middleware;

let app = Router::new()
    .route("/protected", get(protected_handler))
    .layer(middleware::from_fn(authorize_middleware));
// Every request to /protected now receives 403 and protected_handler is not called.
```

The layer only covers routes registered before it in the same `Router`. Attach
it to a dedicated subrouter, or add it after every route, so a route cannot be
added later without the layer:

```rust
let protected = Router::new()
    .route("/protected", get(protected_handler))
    .layer(middleware::from_fn(authorize_middleware));

let app = Router::new()
    .route("/health", get(health))
    .merge(protected);
```

## Why deny everything?

A middleware that cannot evaluate a policy has no safe default. The alternatives
were worse:

- forwarding the request (the previous behavior, a real authorization bypass);
- accepting a client-supplied tenant or role header as identity;
- returning `200` with an empty body while the handler never ran.

The denial is generic: `403 Forbidden` with the body `forbidden`. The
configuration error is logged once per process, not once per request, so
unauthenticated traffic cannot amplify logs or leak request paths.

## Compatibility

- `middleware::AuthorizationState` is retained as a deprecated, unused
  placeholder so `0.1.x` consumers keep compiling. It will be removed when the
  authorizing middleware replaces the fail-closed layer.
- The extractors are not part of this release. Do not build an identity from
  `Authorization` headers, `x-tenant-id`, or any other client-supplied value.
- The stateful adapter that maps an authenticated principal and a scoped
  resource to a Cedar decision belongs to the follow-up authorization work.

## Tests

```bash
cargo test -p hodei-authz-axum
```

`tests/middleware_fail_closed.rs` proves, in-process:

1. a protected GET is denied with `403` and the handler is not reached;
2. a denied POST does not reach the handler;
3. forged `authorization` / `x-tenant-id` headers do not change the denial;
4. a health route outside the layer still returns `200`.

## License

MIT OR Apache-2.0
