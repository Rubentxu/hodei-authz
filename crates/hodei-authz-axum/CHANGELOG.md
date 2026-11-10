# Changelog

## 0.2.0 — authorizing middleware

- Requires `hodei-authz 0.1.1` (the typed contract/Cedar API); `0.1.0` does not
  contain those symbols.

- Added `AuthorizeState`, `AuthorizationTarget`/`Target`, and
  `authorize_with_state`. The middleware verifies a bearer credential through a
  `PrincipalAuthenticator`, resolves a route target, evaluates a real
  `Authorizer`, and forwards only on `Permit`.
- Missing/invalid credentials return `401`; deny/indeterminate return `403`;
  malformed targets return `400`; the handler is not executed in these cases.
- Cross-account targets are denied by default; `AuthorizeState::allow_cross_account`
  is an explicit opt-in for administrative flows.
- The verified `VerifiedContext` is a per-request extension; no mutable state is
  shared between concurrent requests.
- `401` includes a `WWW-Authenticate: Bearer` challenge.
- `authorize_middleware` remains the legacy fail-closed layer for compatibility.

## 0.1.1 — security correction

- `authorize_middleware` no longer forwards protected requests to the handler.
  It fails closed with `403 Forbidden` until a verified authorizer is wired.
  The previous implementation called `next.run(req)` unconditionally, so every
  "protected" route was effectively public.
- The denial body is generic (`forbidden`). The configuration error is logged
  once per process; there is no per-request logging of paths.
- In-process regression tests cover the handler being unreachable, denied
  mutating requests, forged identity headers, and health routes outside the
  layer.
- `middleware::AuthorizationState` is deprecated and retained as an unused
  placeholder for `0.1.x` compatibility.
