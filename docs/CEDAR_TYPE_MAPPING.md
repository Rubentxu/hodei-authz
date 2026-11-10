# Mapping de tipos Cedar

`HrnCedarMapper` deriva el tipo de entidad de `service::resource_type`.

- Los tipos canónicos conocidos (`User`, `Group`, `ServiceAccount`, `Policy`) conservan su forma PascalCase.
- `sanitize` codifica bytes no alfanuméricos como `_xHH`, de modo que `package-version` y `package_version` producen tipos distintos.
- El legacy convertía el primer carácter a mayúsculas; por eso `repository` y `Repository` podían colisionar. Desde HSP-27 un `resource_type` con mayúsculas fuera de la lista canónica se **rechaza fail-closed** con `CedarMappingError`, en lugar de plegarse silenciosamente al tipo lower-case.
- El HRN completo sigue siendo el id de entidad; el rechazo evita además que una política por tipo conceda a una variante semánticamente distinta.
- Los tipos nuevos deben usar la forma canónica en minúsculas (o registrarse explícitamente si necesitan otra forma).

Tests: `tests/hrn_mapper.rs`, incluido `upper_case_resource_type_is_rejected_instead_of_colliding`.
