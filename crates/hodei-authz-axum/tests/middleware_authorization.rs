//! Axum integration tests for the authorizing middleware.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Extension, State};
use axum::http::{Request, StatusCode};
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use cedar_policy::Entities;
use hodei_authz::cedar::CedarAuthorizer;
use hodei_authz::hrn_mapper::HrnCedarMapper;
use hodei_authz::{
    AccountId, ActionId, AuthenticationError, AuthorizationOutcome, Authorizer, Credentials,
    IndeterminateReason, PrincipalAuthenticator, PrincipalClaims, PrincipalId, ResourceRef,
    VerifiedContext,
};
use hodei_authz_axum::{
    AuthorizationTarget, AuthorizeState, Target, TargetError, authorize_with_state,
};
use tower::ServiceExt;

struct TestAuthenticator;

#[async_trait]
impl PrincipalAuthenticator for TestAuthenticator {
    async fn authenticate(
        &self,
        credentials: &Credentials,
    ) -> Result<PrincipalClaims, AuthenticationError> {
        tokio::task::yield_now().await;
        let token = match credentials {
            Credentials::Bearer(token) => token,
            _ => return Err(AuthenticationError::MissingCredentials),
        };
        let (account, name) = match token.as_str() {
            "alice" => ("acme", "alice"),
            "bob" => ("acme", "bob"),
            "carol" => ("other", "carol"),
            "expired" => return Err(AuthenticationError::Expired),
            _ => return Err(AuthenticationError::InvalidCredentials),
        };
        Ok(PrincipalClaims::new(
            PrincipalId::new(format!("hrn:hodei:iam::{account}:User/{name}")).unwrap(),
            AccountId::new(account).unwrap(),
        )
        .with_attributes(BTreeMap::new()))
    }
}

struct PathTarget;

impl AuthorizationTarget for PathTarget {
    fn resolve(&self, request: &Request<Body>) -> Result<Target, TargetError> {
        let path = request
            .uri()
            .path()
            .strip_prefix("/repositories/")
            .ok_or(TargetError::BadRequest)?;
        let mut parts = path.split('/');
        let account = parts
            .next()
            .filter(|part| !part.is_empty())
            .ok_or(TargetError::BadRequest)?;
        let name = parts
            .next()
            .filter(|part| !part.is_empty())
            .ok_or(TargetError::BadRequest)?;
        if parts.next().is_some() {
            return Err(TargetError::BadRequest);
        }

        let resource = format!("hrn:hodei:artifacts:eu:{account}:repository/{name}")
            .parse::<ResourceRef>()
            .map_err(|_| TargetError::BadRequest)?;
        let action = match *request.method() {
            axum::http::Method::GET => ActionId::new("artifacts", "ReadRepository"),
            axum::http::Method::POST
            | axum::http::Method::PUT
            | axum::http::Method::PATCH
            | axum::http::Method::DELETE => ActionId::new("artifacts", "WriteRepository"),
            _ => return Err(TargetError::UnsupportedMethod),
        }
        .map_err(|_| TargetError::Internal)?;

        Ok(Target::new(action, resource))
    }
}

struct IndeterminateAuthorizer;

impl Authorizer for IndeterminateAuthorizer {
    fn decide(&self, _request: &hodei_authz::AuthorizationRequest) -> AuthorizationOutcome {
        AuthorizationOutcome::indeterminate(IndeterminateReason::EvaluationError)
    }
}

fn cedar(policy: &str) -> Arc<dyn Authorizer> {
    Arc::new(
        CedarAuthorizer::from_policies_unchecked(
            policy,
            Entities::empty(),
            Arc::new(HrnCedarMapper),
        )
        .expect("authorizer"),
    )
}

fn app(policy: &str) -> (Router, Arc<AtomicUsize>) {
    let counter = Arc::new(AtomicUsize::new(0));
    let state = AuthorizeState::new(
        Arc::new(TestAuthenticator),
        cedar(policy),
        Arc::new(PathTarget),
    );
    let router = Router::new()
        .route("/repositories/{account}/{name}", get(handler))
        .layer(from_fn_with_state(state, authorize_with_state))
        .with_state(counter.clone());
    (router, counter)
}

async fn handler(
    Extension(context): Extension<VerifiedContext>,
    State(counter): State<Arc<AtomicUsize>>,
) -> String {
    tokio::task::yield_now().await;
    counter.fetch_add(1, Ordering::SeqCst);
    context.account().to_string()
}

async fn call(app: Router, token: Option<&str>, path: &str) -> (StatusCode, String) {
    let mut builder = Request::builder().uri(path);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&body).to_string())
}

const ALICE_ACME: &str = r#"permit(
    principal == Iam::User::"hrn:hodei:iam::acme:User/alice",
    action == Artifacts::Action::"ReadRepository",
    resource == Artifacts::Repository::"hrn:hodei:artifacts:eu:acme:repository/repo"
);"#;

#[tokio::test]
async fn missing_or_invalid_token_is_unauthenticated_and_never_reaches_the_handler() {
    let (app, counter) = app(ALICE_ACME);
    let (status, _) = call(app.clone(), None, "/repositories/acme/repo").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = call(app.clone(), Some("garbage"), "/repositories/acme/repo").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = call(app, Some("expired"), "/repositories/acme/repo").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn forged_tenant_header_is_not_an_identity() {
    let (first_app, counter) = app(ALICE_ACME);
    let request = Request::builder()
        .uri("/repositories/acme/repo")
        .header("x-tenant-id", "acme")
        .body(Body::empty())
        .unwrap();
    let response = first_app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(counter.load(Ordering::SeqCst), 0);

    let (second_app, counter) = app(ALICE_ACME);
    let request = Request::builder()
        .uri("/repositories/acme/repo")
        .header("authorization", "Bearer alice")
        .header("x-tenant-id", "other")
        .body(Body::empty())
        .unwrap();
    let response = second_app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cross_account_is_denied_even_with_a_lax_policy() {
    let policy = r#"permit(
        principal == Iam::User::"hrn:hodei:iam::acme:User/alice",
        action == Artifacts::Action::"ReadRepository",
        resource
    );"#;
    let (app, counter) = app(policy);
    let (status, _) = call(app, Some("alice"), "/repositories/other/repo").await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn permit_forwards_the_verified_context() {
    let (app, counter) = app(ALICE_ACME);
    let (status, body) = call(app, Some("alice"), "/repositories/acme/repo").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "acme");
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn deny_does_not_execute_the_handler() {
    let (app, counter) = app(ALICE_ACME);
    let (status, _) = call(app, Some("bob"), "/repositories/acme/repo").await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn another_accounts_resource_is_denied() {
    let (app, counter) = app(ALICE_ACME);
    let (status, _) = call(app, Some("alice"), "/repositories/other/repo").await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn indeterminate_is_denied() {
    let state = AuthorizeState::new(
        Arc::new(TestAuthenticator),
        Arc::new(IndeterminateAuthorizer),
        Arc::new(PathTarget),
    );
    let counter = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/repositories/{account}/{name}", get(handler))
        .layer(from_fn_with_state(state, authorize_with_state))
        .with_state(counter.clone());

    let (status, _) = call(app, Some("alice"), "/repositories/acme/repo").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_do_not_share_context() {
    let policy = r#"permit(
        principal == Iam::User::"hrn:hodei:iam::acme:User/alice",
        action == Artifacts::Action::"ReadRepository",
        resource
    );
    permit(
        principal == Iam::User::"hrn:hodei:iam::other:User/carol",
        action == Artifacts::Action::"ReadRepository",
        resource
    );"#;
    let (app, counter) = app(policy);
    let mut tasks = Vec::new();
    for index in 0..8 {
        let app = app.clone();
        let (token, path, expected) = if index % 2 == 0 {
            ("alice", "/repositories/acme/repo", "acme")
        } else {
            ("carol", "/repositories/other/repo", "other")
        };
        tasks.push(tokio::spawn(async move {
            let (status, body) = call(app, Some(token), path).await;
            (status, body, expected)
        }));
    }

    for task in tasks {
        let (status, body, expected) = task.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, expected);
    }
    assert_eq!(counter.load(Ordering::SeqCst), 8);
}

#[tokio::test]
async fn unsupported_method_is_rejected() {
    let (app, counter) = app(ALICE_ACME);
    let request = Request::builder()
        .method("TRACE")
        .uri("/repositories/acme/repo")
        .header("authorization", "Bearer alice")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn malformed_target_is_a_bad_request() {
    let (app, counter) = app(ALICE_ACME);
    let (status, _) = call(app, Some("alice"), "/not-a-repository").await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}
