# Changelog

## 0.1.1 — typed authorization core

- Added the typed authorization contract (`PrincipalClaims`, `VerifiedPrincipal`,
  `VerifiedContext`, `ResourceRef`, `ActionId`, `AuthorizationRequest`,
  `Permit`/`Deny`/`Indeterminate`) and the authentication/authorization ports.
- Added the fail-closed `CedarAuthorizer` with schema validation, action groups,
  request attributes and diagnostics.
- Added `HrnCedarMapper` with canonical HRN scope and group/resource parents.
- These APIs are additive; `hodei-authz 0.1.0` does not contain them.
