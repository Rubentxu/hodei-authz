# HRN → identidad Cedar

`HrnCedarMapper` es el mapper de producción del MVP. Convierte un HRN completo en una identidad Cedar estable, inyectiva y con el scope de cuenta/región/servicio intacto.

## Formato

| Elemento | Regla |
| --- | --- |
| Tipo Cedar | `<Service>::<ResourceType>` (servicio y tipo capitalizados, sin prefijo adicional) |
| Id Cedar | El HRN canónico completo, por ejemplo `hrn:hodei:artifacts:eu:acme:repository/releases` |
| Principal | HRN del `subject`; `Iam::User` para `hrn:hodei:iam::acme:User/alice` |
| Grupos | `Iam::Group::"hrn:hodei:iam::<account>:Group/<group>"` |
| Parents de recurso | Prefijos de `resource_id` separados por `/` |
| Acciones | `ActionId` canónico, separado del mapper: `Artifacts::Action::"ReadRepository"` |

El id completo incluye cuenta, región, servicio y tipo. Dos recursos con el mismo id local en cuentas distintas producen UIDs distintos:

```text
hrn:hodei:artifacts:eu:acme:repository/releases
hrn:hodei:artifacts:eu:other:repository/releases
→ Artifacts::Repository::"hrn:hodei:artifacts:eu:acme:repository/releases"
→ Artifacts::Repository::"hrn:hodei:artifacts:eu:other:repository/releases"
```

## Grupos y jerarquías

- `VerifiedPrincipal.groups()` se traduce a parents `Iam::Group` con la cuenta del principal. Un `forbid` con `principal in Iam::Group::"..."` funciona.
- Los grupos son planos: no se inventan jerarquías de grupos. Un grupo padre debe modelarse como otro parent explícito en el snapshot base o en una extensión futura.
- `resource_parents` añade los prefijos de `resource_id` (`repository/releases/v2` → `repository/releases` y `repository`). El parser `Hrn` 0.1 solo acepta dos partes de recurso; para probar paths anidados se construye el `Hrn` directamente. El parser canónico completo llega con HSP-12. Un `resource_id` con segmentos vacíos, `.` o `..` se rechaza.
- La migración de un snapshot legacy exige reescribir sus entidades al UID canónico: el merge de HSP-6 es por UID exacto y no fusiona `repository`/`HodeiMVP::*` con `artifacts`/`Iam::*`.
- El mapper es TCB y debe ser puro/determinista. No crea entidades de grupo ni de recurso por sí mismo: el evaluador construye las entidades del request y Cedar calcula la clausura.
- El mapper exige que el `subject` sea un HRN de **principal IAM** (`User` o `ServiceAccount`, servicio `iam`). Un subject opaco, un grupo o un recurso produce error de mapeo (`Indeterminate`), no una identidad inventada; así un subject con forma de `Group` no puede autoconcederse pertenencia.
- La gramática se valida antes de construir el UID: servicio minúsculas con `-`, tipo alfanumérico que empieza por letra, cuenta `[A-Za-z0-9_-]`, recurso sin controles/comillas/backslash. Un `Hrn` construido a mano con segmentos inválidos se rechaza.

## Acciones

Las acciones **no** pasan por `HrnCedarMapper`. `ActionId` ya produce el UID canónico `Service::Action::"name"` (servicio en minúsculas, namespace inyectivo). El test `action_uid_matches_the_canonical_schema_name` fija el literal/round-trip; la coincidencia real con un schema validado está en `mapper_works_with_the_validated_schema_path` (HSP-7) y en `validated_schema_path_can_permit` (HSP-6).

## Migración legacy

`HrnCedarMapper` no conserva decisiones de identidades antiguas: un HRN con servicio `repository` produce un tipo/UID distinto de `artifacts`, y las políticas que referenciaban el UID antiguo dejan de aplicar. La diferencia está registrada y probada en `legacy_repository_service_maps_to_a_different_uid`.

- `hrn:hodei:repository:eu:acme:repository/releases` → `Repository::Repository::"..."`
- `hrn:hodei:artifacts:eu:acme:repository/releases` → `Artifacts::Repository::"..."`

Deltas de migración registrados:

| Elemento | Antiguo | Canónico HSP-7 |
| --- | --- | --- |
| Servicio de recurso | `repository` | `artifacts` |
| Tipo de entidad | `HodeiMVP::Repository` / `User` / `Artifacts::*` | `Artifacts::Repository` / `Iam::User` |
| Grupo | `Group::"developers"` | `Iam::Group::"hrn:hodei:iam::<account>:Group/developers"` |
| Acción | `Document::Create`, `DocApp::Action::"Document::Read"` | `ActionId` canónico (`Artifacts::Action::"..."`) |

No hay alias silencioso. `canonical_policy_does_not_match_a_legacy_identity` prueba que una política canónica no concede sobre un recurso legacy; `ActionId` rechaza las acciones legacy con `:`. La migración de políticas/entidades debe hacerse antes de HSP-12; el dominio IAM de Artifacts no se traslada al core.

## Pruebas

`tests/hrn_mapper.rs` cubre:

- mismo id local en cuentas distintas → UIDs distintos;
- principal y `owner_id` HRN → mismo UID;
- grupos con cuenta y `forbid` por pertenencia;
- parents de recurso por prefijos;
- acción canónica, path validado con schema y coincidencia con el evaluador;
- diferencia `repository` → `artifacts` y política canónica que no aplica a identidad legacy;
- path de schema validado con `from_policies`;
- subject no HRN, subject con forma de grupo/recurso, recurso sin parents y con parent evaluado, grupo de otra cuenta, campos ambiguos/vacíos y partición distinta;
- rechazo de referencias que no son HRN.

## Límites

- `Hrn` 0.1 en este workspace; el parser canónico completo es HSP-12. La gramática del mapper es más estricta que el parser 0.1, pero los paths anidados construidos a mano dependen de esa validación local.
- Grupos planos, sin jerarquía IAM ni migración del dominio IAM de Artifacts. El tipo `Iam::Group` es la convención MVP.
- El schema de producción debe declarar `Iam::User`, `Iam::Group`, `Artifacts::Repository` y las acciones canónicas; HSP-14 asegura ese esquema.
- Sin IO, red ni servicio remoto.
