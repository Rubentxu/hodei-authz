# Separación del adaptador Cedar

**Decisión: KEEP_AS_IS.** El adaptador Cedar permanece en `hodei-authz`; no se extrae un crate `hodei-authz-cedar` en este ciclo.

**Fecha:** 2026-11-10 · **Tarea:** HSP-9 (HSEC-AZ-06) · **Autor:** @lead

## Acoplamiento real

- `CedarAuthorizer` vive en `crates/hodei-authz/src/cedar.rs`, pero Cedar **no** está confinado a ese archivo: `api.rs`, `internal/domain.rs`, `traits.rs` (`PolicyStore::load_all_policies -> PolicySet`), `hrn_mapper.rs` y `lib.rs` usan o reexportan tipos `cedar-policy`. `cedar-policy` es una dependencia no opcional de `hodei-authz`.
- Por tanto hoy **no existe** un subconjunto del contrato que compile sin Cedar. Extraer un crate exigiría mover también el mapper de producción, parte de `api`, el modelo interno y rediseñar `PolicyStore`, con ruptura de la API `0.1.2` ya publicada.
- `hodei-authz-axum 0.2.1` solo declara `axum`, `hodei-authz`, `thiserror` y `tracing` en runtime; consume `Arc<dyn Authorizer>` y `decide()`. Cedar aparece únicamente como `dev-dependency` para sus tests de integración.

## Alternativa evaluada

Se consideró hacer `cedar` opcional mediante una feature en el mismo crate. También rompe la superficie pública actual (`PolicyStore`, `CedarEntityMapper`, reexports) y no hay un consumidor identificado que necesite el contrato sin Cedar; añadir la feature sin ese consumidor aumenta la matriz de compilación y el mantenimiento. Se descarta hasta que exista esa necesidad medida.

## Verificación publicada

- Fecha de publicación: 2026-11-10.
- [`hodei-authz 0.1.2`](https://crates.io/crates/hodei-authz/0.1.2) y [`hodei-authz-axum 0.2.1`](https://crates.io/crates/hodei-authz-axum/0.2.1) están en crates.io. Los adaptadores `hodei-authz-postgres`, `hodei-authz-redis` y `hodei-authz-sdk 0.1.0` ya estaban publicados.
- Consumidor reproducible en el repo: `examples/published-consumer`, aislado del workspace, con dependencias `hodei-authz = "0.1.2"`, `hodei-authz-axum = "0.2.1"` y sin paths:

  ```text
  cargo run --manifest-path examples/published-consumer/Cargo.toml
  published authz consumer OK: alice=Permit bob=Deny
  ```

  El ejemplo usa `CedarAuthorizer` + `HrnCedarMapper`, verifica `alice → Permit` y `bob → Deny(NoMatchingPolicy)`, y comprueba que el crate Axum publicado está en el grafo.

- Fail-closed de Axum cubierto por `crates/hodei-authz-axum/tests/middleware_fail_closed.rs` y `middleware_authorization.rs` (sin authorizer, mutación denegada, headers forjados, health fuera de la capa).

## Cuándo revisar

Si aparece un consumidor real que deba compilar el contrato sin Cedar, se reevalúa la extracción o la feature con esa evidencia. HSP-18 consume los crates publicados y no requiere el crate nuevo.
