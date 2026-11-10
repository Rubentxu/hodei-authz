# Evaluación Cedar

Adaptador puro de `hodei-authz` para Cedar. El núcleo funcional no depende de Cedar; este módulo traduce un `AuthorizationRequest` tipado a una petición Cedar y devuelve un `AuthorizationOutcome` fail-closed.

## Construcción segura

```rust
use std::sync::Arc;
use cedar_policy::Entities;
use hodei_authz::cedar::CedarAuthorizer;

let authorizer = CedarAuthorizer::from_policies(
    policies,
    Entities::empty(),
    Arc::new(mapper),
    schema, // obligatorio: se valida en modo estricto
)?;
```

- `from_policies` **exige** un `Schema`, parsea el `PolicySet`, lo valida en modo estricto y valida el snapshot base. Cedar añade las entidades de acción del schema (incluidos action groups). Políticas inválidas, entidades no conformes o acciones desconocidas no producen authorizer.
- `from_policies_unchecked` es la única vía sin schema; no valida ni añade action entities. Su nombre y su documentación la marcan como escape para tests o políticas estáticas plenamente confiables. No se usa en producción.
- El snapshot base (`PolicySet`, `Entities`) es inmutable; no hay IO, red ni servicio remoto. Las entidades del principal y del recurso se construyen **por petición** con sus atributos y los UIDs/parents del mapper.

## Decisión

```rust
match authorizer.decide(&request) {
    Permit => allow,
    Deny(reason) => deny,
    Indeterminate(reason) => deny,
}
```

- `Allow` de Cedar → `Permit`.
- `Deny` con `reason` no vacío → `Deny(ExplicitForbid)`.
- `Deny` sin políticas aplicables → `Deny(NoMatchingPolicy)`.
- Errores de evaluación de Cedar → `Indeterminate(EvaluationError)`; `decide_with_diagnostics` conserva el texto técnico.
- Errores de mapeo, contexto o `Request` → `Indeterminate(EvaluationError)`; nunca `Permit`.
- Un policy set vacío **no** evita el mapeo: si el mapper o el contexto fallan, el resultado es `Indeterminate`, no un `Deny` que oculte el fallo.
- El diagnóstico es para logs/observabilidad interna; no debe devolverse al cliente.

## Entidades y contexto

`HrnCedarMapper` (ver [HRN_MAPPING.md](HRN_MAPPING.md)) es el mapper de producción; `CedarEntityMapper` es el seam y forma parte de la TCB: decide los UIDs y parents de `VerifiedPrincipal` y `ResourceRef`, y traduce referencias `AttributeValue::Entity` (por ejemplo el HRN de `owner_id`) a un UID Cedar. El evaluador no inventa tipos ni UIDs a partir de strings no verificados. Las implementaciones **deben ser puras y deterministas**: no IO, reloj ni aleatoriedad.

El evaluador construye las entidades del principal y del recurso en cada decisión, inyectando los atributos del request (`String`, `Bool`, `Long`, `Entity`, `Set<String>`) como atributos Cedar. Así `principal.role` y `resource.owner_id` son evaluables con el payload tipado. Si el snapshot base ya contiene una entidad con el mismo UID, se **fusiona**: se conservan sus parents y atributos y el request solo sobrescribe los atributos con el mismo nombre. Los parents que devuelve el mapper se añaden a los de la entidad base.

`AttributeValue::Set` solo admite strings en este contrato; `Entity` se resuelve con `CedarEntityMapper::entity_reference`. El mapper **debe** codificar el tenant/cuenta en el UID para no colapsar identidades de cuentas distintas (HSP-7). El `TestMapper` de los tests no es un mapper de producción.

## Pruebas

`tests/cedar_evaluation.rs` cubre, sin IO:

- permit y camino positivo con schema validado,
- default deny sin políticas y con política no aplicable,
- forbid explícito sobre permit y forbid que no aplica,
- action group (`memberOf`) desde el schema y parents de una entidad base preservados,
- permit + forbid con error de evaluación → Indeterminate (no Permit),
- política inválida (no construye) y schema que rechaza una acción desconocida,
- atributos de entidad (`role`, `owner_id` HRN→UID) y de contexto (`Bool`, `Long`, `Entity`, `Set`),
- `Entity` de contexto inválida → Indeterminate,
- policy set vacío + error de mapeo → Indeterminate con diagnóstico,
- error de mapeo → Indeterminate con diagnóstico.

## Límites

- HSP-6 no carga entidades ni recursos: recibe snapshots y construye las entidades del request.
- La normalización completa HRN→Cedar, parents, jerarquías y el encoding de tenant en UIDs es HSP-7.
- El schema positivo y los `InvalidContext` dependen del schema real de HSP-7; el test actual cubre el camino validado y el rechazo por schema.
- `AttributeValue::Set` solo strings; conjuntos de entidades/longs quedan para una extensión del contrato.
- No hay servicio remoto de políticas ni Redis.
