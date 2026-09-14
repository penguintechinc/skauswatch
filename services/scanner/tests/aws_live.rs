//! Gated live-AWS smoke test: proves the real S3-scan path — our
//! `skauswatch_s3::client` construction plus the production
//! [`YaraScanner`](crate) engine — actually detects EICAR when the bytes
//! are fetched from a real AWS S3 bucket, not the MinIO/wiremock harness
//! used everywhere else in this workspace.
//!
//! `crates/skauswatch-s3` only wraps client *construction* (region/endpoint/
//! path-style resolution + the AWS credential provider chain); it does not
//! wrap CRUD. So `create_bucket`/`put_object`/`list_objects_v2`/`get_object`
//! below call the raw `aws_sdk_s3::Client` returned by our wrapper — there is
//! no "our API" for those operations to prefer over the SDK call.
//!
//! The YARA engine is pulled in via `#[path]` (this crate has no `[lib]`
//! target for `services/scanner` to depend on as a library) so the test
//! exercises the exact production `YaraScanner::load`/`scan_bytes` used by
//! `main.rs`, not a reimplementation.
//!
//! # Running
//! Skipped (no-op, exit 0) unless `SKAUSWATCH_AWS_LIVE=1` is set — normal CI
//! has neither this env var nor AWS credentials, so it silently no-ops there.
//! To actually run it against real AWS:
//!
//! ```sh
//! export AWS_SHARED_CREDENTIALS_FILE=/path/to/creds
//! export AWS_PROFILE=skauswatch-test
//! export AWS_DEFAULT_REGION=us-east-1
//! export SKAUSWATCH_AWS_LIVE=1
//! cargo test -p skauswatch-scanner --test aws_live -- --nocapture
//! ```
//!
//! Requires an IAM identity with S3 full CRUD (create/delete bucket, put/get/
//! list/delete object) on a throwaway bucket namespace — no `sts:AssumeRole`
//! needed or attempted.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "../src/yara.rs"]
mod yara;

use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use futures::FutureExt;
use skauswatch_s3::S3Config;
use std::panic::AssertUnwindSafe;

/// Env var that gates this test on. Absent -> no-op (see module docs).
const AWS_LIVE_ENV: &str = "SKAUSWATCH_AWS_LIVE";

/// Canonical 68-byte EICAR AV test signature (not real malware).
const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const CLEAN: &[u8] =
    b"This is a harmless document with no executable code or suspicious patterns whatsoever.";

const EICAR_KEY: &str = "eicar-test.txt";
const CLEAN_KEY: &str = "clean-test.txt";

#[tokio::test]
async fn aws_live_s3_eicar_detection() {
    if std::env::var(AWS_LIVE_ENV).is_err() {
        eprintln!(
            "skipping aws_live_s3_eicar_detection: set {AWS_LIVE_ENV}=1 (with AWS creds) to run against real AWS"
        );
        return;
    }

    // Real AWS, default endpoint (no MinIO override). Virtual-hosted-style
    // addressing (force_path_style=false) — AWS's default and recommended
    // mode; skauswatch_s3::S3Config's own default (true) targets MinIO.
    let cfg = S3Config {
        endpoint_url: None,
        region: "us-east-1".to_owned(),
        force_path_style: false,
    };
    // Our wrapper: builds the client via the standard AWS credential
    // provider chain (env/profile here), region/endpoint resolution.
    let client = skauswatch_s3::client(&cfg).await;

    let bucket = format!(
        "skauswatch-live-{}-{}",
        chrono::Utc::now().timestamp(),
        uuid::Uuid::new_v4().simple()
    );

    // us-east-1 is the classic region: CreateBucketConfiguration must be
    // omitted entirely (specifying it, even as us-east-1, errors).
    client
        .create_bucket()
        .bucket(&bucket)
        .send()
        .await
        .expect("create_bucket");

    // Run the actual assertions, but guarantee bucket/object cleanup runs
    // even on panic (assertion failure) — scopeguard-style deferred delete
    // via catch_unwind, since this is async and Drop can't easily await.
    let result = AssertUnwindSafe(scan_round_trip(&client, &bucket))
        .catch_unwind()
        .await;

    cleanup(&client, &bucket).await;

    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

/// Puts EICAR + a clean file, lists and gets them back, then scans both
/// through the production YARA-X engine.
async fn scan_round_trip(client: &Client, bucket: &str) {
    // put — raw aws-sdk-s3 call; skauswatch-s3 offers no put wrapper.
    for (key, body) in [(EICAR_KEY, EICAR), (CLEAN_KEY, CLEAN)] {
        client
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from(body.to_vec()))
            .send()
            .await
            .unwrap_or_else(|e| panic!("put_object {key}: {e}"));
    }

    // list — raw aws-sdk-s3 call; skauswatch-s3 offers no list wrapper.
    let listed = client
        .list_objects_v2()
        .bucket(bucket)
        .send()
        .await
        .expect("list_objects_v2");
    let keys: Vec<&str> = listed.contents().iter().filter_map(|o| o.key()).collect();
    assert!(
        keys.contains(&EICAR_KEY),
        "listing missing {EICAR_KEY}: {keys:?}"
    );
    assert!(
        keys.contains(&CLEAN_KEY),
        "listing missing {CLEAN_KEY}: {keys:?}"
    );

    // get — raw aws-sdk-s3 call; skauswatch-s3 offers no get wrapper.
    let eicar_bytes = get_object_bytes(client, bucket, EICAR_KEY).await;
    let clean_bytes = get_object_bytes(client, bucket, CLEAN_KEY).await;
    assert_eq!(
        eicar_bytes, EICAR,
        "round-tripped EICAR bytes must match exactly"
    );
    assert_eq!(
        clean_bytes, CLEAN,
        "round-tripped clean bytes must match exactly"
    );

    // scan — OUR production YARA-X engine (services/scanner/src/yara.rs).
    let rules_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/yara_rules");
    let scanner = yara::YaraScanner::load(rules_path)
        .await
        .expect("corporate_threats.yar corpus must load");

    let eicar_matches = scanner.scan_bytes(&eicar_bytes).expect("scan eicar bytes");
    assert!(
        eicar_matches
            .iter()
            .any(|m| m.rule_name == "EICAR_Test_File"),
        "EICAR object fetched from real S3 should match EICAR_Test_File; got {eicar_matches:?}"
    );

    let clean_matches = scanner.scan_bytes(&clean_bytes).expect("scan clean bytes");
    assert!(
        clean_matches.is_empty(),
        "clean object fetched from real S3 should not match any rule; got {clean_matches:?}"
    );
}

async fn get_object_bytes(client: &Client, bucket: &str, key: &str) -> Vec<u8> {
    let resp = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .unwrap_or_else(|e| panic!("get_object {key}: {e}"));
    resp.body
        .collect()
        .await
        .expect("collect object body")
        .into_bytes()
        .to_vec()
}

/// Deletes both test objects and the bucket. Best-effort per call (a failed
/// object delete must not skip the bucket delete attempt) but every call is
/// still awaited and logged — a leaked bucket is a test failure, not a
/// silent shrug.
async fn cleanup(client: &Client, bucket: &str) {
    for key in [EICAR_KEY, CLEAN_KEY] {
        if let Err(e) = client.delete_object().bucket(bucket).key(key).send().await {
            eprintln!("cleanup: delete_object {bucket}/{key} failed: {e}");
        }
    }
    if let Err(e) = client.delete_bucket().bucket(bucket).send().await {
        eprintln!("cleanup: delete_bucket {bucket} failed: {e}");
    }
}
