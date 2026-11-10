//! Tests for HRN (Hodei Resource Name)

use hodei_hrn::Hrn;

#[test]
fn test_hrn_builder_basic() {
    let hrn = Hrn::builder()
        .service("test-service")
        .tenant_id("tenant-1")
        .resource("user/123")
        .unwrap()
        .build()
        .unwrap();

    assert_eq!(hrn.service, "test-service");
    assert_eq!(hrn.tenant_id, "tenant-1");
    assert_eq!(hrn.resource_type, "user");
    assert_eq!(hrn.resource_id, "123");
}

#[test]
fn test_hrn_to_string() {
    let hrn = Hrn::builder()
        .service("documents-api")
        .tenant_id("tenant-a")
        .resource("document/doc-1")
        .unwrap()
        .build()
        .unwrap();

    let expected = "hrn:hodei:documents-api:global:tenant-a:document/doc-1";
    assert_eq!(hrn.to_string(), expected);
}

#[test]
fn test_hrn_from_string() {
    let hrn_str = "hrn:hodei:users-api:global:tenant-b:user/alice";
    let hrn = hrn_str.parse::<Hrn>().unwrap();

    assert_eq!(hrn.service, "users-api");
    assert_eq!(hrn.tenant_id, "tenant-b");
    assert_eq!(hrn.resource_type, "user");
    assert_eq!(hrn.resource_id, "alice");
}

#[test]
fn test_hrn_roundtrip() {
    let original = Hrn::builder()
        .service("test")
        .tenant_id("t1")
        .resource("resource/r1")
        .unwrap()
        .build()
        .unwrap();

    let hrn_str = original.to_string();
    let parsed: Hrn = hrn_str.parse().unwrap();

    assert_eq!(original, parsed);
}

#[test]
fn test_hrn_serialization() {
    let hrn = Hrn::builder()
        .service("test")
        .tenant_id("t1")
        .resource("r/1")
        .unwrap()
        .build()
        .unwrap();

    let json = serde_json::to_string(&hrn).unwrap();
    let deserialized: Hrn = serde_json::from_str(&json).unwrap();

    assert_eq!(hrn, deserialized);
}

#[test]
fn test_hrn_with_complex_resource_id() {
    let hrn = Hrn::builder()
        .service("api")
        .tenant_id("tenant-123")
        .resource("document/folder/subfolder/file.txt")
        .unwrap()
        .build()
        .unwrap();

    assert_eq!(hrn.resource_type, "document");
    assert_eq!(hrn.resource_id, "folder/subfolder/file.txt");
}

#[test]
fn test_hrn_equality() {
    let hrn1 = Hrn::builder()
        .service("svc")
        .tenant_id("t1")
        .resource("user/1")
        .unwrap()
        .build()
        .unwrap();

    let hrn2 = Hrn::builder()
        .service("svc")
        .tenant_id("t1")
        .resource("user/1")
        .unwrap()
        .build()
        .unwrap();

    assert_eq!(hrn1, hrn2);
}

#[test]
fn test_hrn_clone() {
    let hrn = Hrn::builder()
        .service("svc")
        .tenant_id("t1")
        .resource("user/1")
        .unwrap()
        .build()
        .unwrap();

    let cloned = hrn.clone();
    assert_eq!(hrn, cloned);
}
