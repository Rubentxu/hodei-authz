# Contrato de autorización tipado

Núcleo funcional de `hodei-authz`: separa identidad verificada de datos aportados por el cliente y representa decisiones explícitas. No depende de Axum, base de datos ni Tokio.

## Frontera de confianza

| Tipo | Confianza | Construcción |
| --- | --- | --- |
| `PrincipalClaims` | **No verificada** | La produce un authenticator; puede venir de claims de un token |
| `VerifiedPrincipal` | Aceptada por el authenticator configurado | Solo `verify_principal(&authenticator, &credentials)` |
| `Credentials` | Entrada del adaptador | `Bearer`; su `Debug` redacta el token |
| `VerifiedContext` | Verificada | Solo desde un `VerifiedPrincipal` |
| `ResourceRef` | Identidad del recurso | `Hrn` + cuenta derivada del tenant + atributos |
| `AuthorizationRequest` | Petición completa | `VerifiedContext` + `ActionId` + `ResourceRef` + contexto |

No existe constructor público de `VerifiedPrincipal`, `From<PrincipalClaims>`, `From<HeaderMap>` ni deserialización de `VerifiedPrincipal`. Los doctests `compile_fail` E0451/E0308/E0277 de `model.rs` fijan la privacidad de campos, el rechazo de claims como contexto y la ausencia de serde.

**El authenticator es parte de la TCB.** Un adaptador que ignore las credenciales y copie `x-tenant-id` anula la garantía; el trait hace explícita esa decisión, no la valida criptográficamente. Las implementaciones de test (`MockAuthenticator`) solo existen para probar el contrato.

## Uso

```rust
use std::collections::BTreeMap;
use std::error::Error;

use hodei_authz::{
    ActionId, AttributeValue, AuthorizationRequest, Credentials, ResourceRef,
    VerifiedContext, verify_principal,
};
use hodei_authz::hodei_hrn::Hrn;

async fn authorize(
    authenticator: &dyn hodei_authz::PrincipalAuthenticator,
    authorizer: &dyn hodei_authz::Authorizer,
    token: &str,
) -> Result<bool, Box<dyn Error>> {
    let principal = verify_principal(authenticator, &Credentials::bearer(token)).await?;
    let hrn: Hrn = "hrn:hodei:artifacts:eu-west-1:acme:repository/releases"
        .parse()
        .expect("HRN");
    let resource = ResourceRef::new(hrn)?.with_attributes(BTreeMap::from([(
        String::from("is_public"),
        AttributeValue::Bool(false),
    )]));
    let action = ActionId::new("artifacts", "ReadRepository")?;
    let request = AuthorizationRequest::new(
        VerifiedContext::from_principal(principal),
        action,
        resource,
    );
    Ok(authorizer.decide(&request).allows_access())
}
```

## Decisiones

```rust
pub enum AuthorizationOutcome {
    Permit,
    Deny(DenyReason),
    Indeterminate(IndeterminateReason),
}
```

- Solo `Permit` permite acceso; `allows_access()` devuelve `false` para Deny e Indeterminate.
- `Deny` distingue `ExplicitForbid`, `NoMatchingPolicy`, `ScopeMismatch` u `Other`.
- `Indeterminate` distingue `MissingPolicy`, `MissingContext`, `EvaluationError` u `Other`.
- El resultado no se reduce a `bool`: un fallo de evaluación no se convierte en permiso.
- `AuthorizationOutcome` es `#[must_use]`; los adaptadores no pueden ignorarlo sin advertencia.

## Puertos

- `PrincipalAuthenticator`: adapter que valida credenciales y devuelve `PrincipalClaims`. `verify_principal` es el único constructor de `VerifiedPrincipal`.
- `Authorizer`: función pura `decide(&AuthorizationRequest) -> AuthorizationOutcome`. El request lleva principal, acción, recurso, atributos de ambos y contexto; el adapter mantiene el snapshot de políticas. No hace IO: cargar el recurso desde persistencia es responsabilidad del caso de uso.
- El payload cubre las políticas del MVP que dependen de identidad, cuenta, `is_public` y `owner_id`. Jerarquías de padres, grupos anidados o entidades adicionales requieren el snapshot de HSP-7; no se finge que el request sea autosuficiente para cualquier política Cedar.
- El nombre `Authorizer` colisiona con `cedar_policy::Authorizer`; si se importan ambos, usar `hodei_authz::Authorizer as HodeiAuthorizer`.

## Identidad y cuenta

- `VerifiedPrincipal` lleva `subject`, `account`, grupos y atributos verificados.
- Si `subject` es un HRN, `verify_principal` exige que su tenant coincida con `account`; un authenticator que devuelva claims incoherentes falla como `InvalidCredentials`.
- `ResourceRef::new(hrn)` **deriva la cuenta del tenant del HRN**, no la acepta como un campo independiente. Un HRN de otra cuenta produce un `AccountId` distinto y `is_same_account()` es `false`.
- Los atributos del recurso y del contexto (`is_public`, `owner_id`, `ip_address`, etc.) **no vienen de headers**: el caso de uso los carga de una fuente confiable y construye el `ResourceRef`/request. `owner_id` se representa como `AttributeValue::Entity`; `is_public` como `Bool`.
- El `Hrn` 0.1 actual solo parsea dos partes de recurso; un path anidado (`repository/releases/v2`) no se puede representar hasta HSP-7/HSP-12. `ResourceRef::new` rechaza `Action` como tipo de recurso, service con mayúsculas y valores con comillas/backslash/controles, pero la validación completa es del parser canónico futuro.
- `AuthorizationRequest::is_same_account()` expone el ámbito; un request cross-account no se rechaza en el tipo porque una política explícita puede autorizarlo. El autorizador debe decidir con el ámbito visible.
- `ResourceRef` usa el `Hrn` 0.1 actual; HSP-7/HSP-12 lo sustituyen por el parser canónico 0.2. Hasta entonces, `Hrn::from_str` es el límite de validación y no debe recibir strings sin parsear.

## Acciones

`ActionId` replica el contrato canónico de acción: `service` en minúsculas, namespace inyectivo (`-` → `_`, primera letra mayúscula) y nombre `[A-Za-z0-9][A-Za-z0-9_-]*`. `ActionId::new("Artifacts", "read")` y `ActionId::new("artifacts", "read")` son iguales y serializan `Artifacts::Action::"read"`. `from_cedar_uid` solo acepta la forma canónica.

Este tipo es una réplica local mientras `hodei-hrn` 0.2 no esté publicado en este workspace; HSP-2/HSP-7 lo sustituyen por un re-export sin cambiar la semántica. Serializa como su UID Cedar y limita la entrada a 512 bytes.

Las acciones persistidas del ejemplo antiguo (`DocApp::Action::"Document::Read"`) **no** son representables: el separador `:` no pertenece al nombre canónico y el namespace `DocApp` no coincide con `Docapp`. HSP-7 debe migrarlas; no se aceptan silenciosamente.

## Compatibilidad

La API existente (`api`, `traits`, `PolicyStore`, `CacheInvalidation`) no cambia. Este módulo es aditivo a 0.1; la migración de los adaptadores es HSP-6/HSP-8. No se añade una librería "security-common": los tipos viven en `hodei-authz`, que es su propietario.

## Evolución

- `AuthorizationOutcome` es cerrado y fail-closed: añadir una variante es breaking y obliga a revisar los `match`.
- `Credentials` es `#[non_exhaustive]` para admitir API key/mTLS sin romper consumidores.
- `DenyReason`/`IndeterminateReason`/`AuthenticationError`/`ModelError` son `#[non_exhaustive]`.
- Los mensajes de error de proveedor no deben incluir tokens; `ProviderUnavailable` es responsabilidad del adaptador.
