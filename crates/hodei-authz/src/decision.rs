//! Explicit authorization outcomes.
//!
//! An outcome is not a `bool`: `Deny` and `Indeterminate` are different
//! failures and both deny access.

/// Why a policy explicitly denied the request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DenyReason {
    ExplicitForbid,
    NoMatchingPolicy,
    ScopeMismatch,
    Other(String),
}

/// Why the evaluator could not reach a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IndeterminateReason {
    MissingPolicy,
    MissingContext,
    EvaluationError,
    Other(String),
}

/// Result of an authorization decision.
///
/// The variants are closed: adding one is a breaking change, and the default
/// behavior of `allows_access` is fail-closed.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationOutcome {
    Permit,
    Deny(DenyReason),
    Indeterminate(IndeterminateReason),
}

impl AuthorizationOutcome {
    pub fn allow() -> Self {
        Self::Permit
    }

    pub fn deny(reason: DenyReason) -> Self {
        Self::Deny(reason)
    }

    pub fn indeterminate(reason: IndeterminateReason) -> Self {
        Self::Indeterminate(reason)
    }

    /// Only `Permit` allows access; `Deny` and `Indeterminate` do not.
    #[must_use]
    pub fn allows_access(&self) -> bool {
        matches!(self, Self::Permit)
    }

    #[must_use]
    pub fn is_permit(&self) -> bool {
        self.allows_access()
    }
}
