# CI de Authz

El workflow `.github/workflows/ci.yml` verifica en cada PR/push:

- formato (`cargo fmt --all -- --check`);
- clippy sin dependencias de PostgreSQL/Redis (`-p hodei-authz -p hodei-authz-axum --no-deps -D warnings`);
- tests del contrato y del middleware Axum;
- el consumidor publicado `examples/published-consumer`, que resuelve `hodei-authz 0.1.2` y `hodei-authz-axum 0.2.1` desde crates.io y exige `alice=Permit`, `bob=Deny`;
- `cargo package` del core y Axum (sin publicar).

No requiere secretos, PostgreSQL ni Redis. La publicación sigue siendo un paso manual/authorized release, no lo dispara la CI. El commit bajo prueba se registra en el log del job.
