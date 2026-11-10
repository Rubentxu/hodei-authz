# Changelog

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
