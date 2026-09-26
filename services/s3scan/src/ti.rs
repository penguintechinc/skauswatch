//! Threat-intel enrichment ported from v1 `ti/enricher.py`. Produces the same
//! result dict shape (`vt_score`, `otx_pulses`, `threat_family`, `severity`,
//! `related_iocs`) stored in the `ti_enrichment` jsonb column. VirusTotal and
//! OTX lookups only fire when their API keys are configured; otherwise the
//! enrichment degrades to a family guess derived from the scan's threat names,
//! exactly as v1 did when the network calls returned nothing.

use serde_json::json;

use crate::scan::Hashes;

/// VirusTotal file-report base URL (v1 `VT_BASE_URL`).
const VT_BASE_URL: &str = "https://www.virustotal.com/api/v3";
/// OTX file-pulses base URL (v1 `OTX_BASE_URL`).
const OTX_BASE_URL: &str = "https://otx.alienvault.com/api/v1";

/// Maps a VirusTotal detection ratio (0–100) to a severity label (v1
/// `_calculate_severity`).
pub fn calculate_severity(detection_ratio: f64) -> &'static str {
    if detection_ratio >= 75.0 {
        "critical"
    } else if detection_ratio >= 50.0 {
        "high"
    } else if detection_ratio >= 25.0 {
        "medium"
    } else if detection_ratio > 0.0 {
        "low"
    } else {
        "unknown"
    }
}

/// Strips a platform prefix off the first threat name to guess a family (v1
/// `_extract_family_from_names`).
pub fn extract_family_from_names(threat_names: &[String]) -> Option<String> {
    let first = threat_names.first()?;
    const PREFIXES: [&str; 6] = ["Win32.", "Win64.", "Android.", "Linux.", "OSX.", "YARA_"];
    let mut name = first.as_str();
    for p in PREFIXES {
        if let Some(rest) = name.strip_prefix(p) {
            name = rest;
            break;
        }
    }
    if name.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

/// The v1 default enrichment dict (no network data), with `threat_family`
/// filled in from the scan's threat names when possible.
pub fn default_result(threat_names: &[String]) -> serde_json::Value {
    json!({
        "vt_score": serde_json::Value::Null,
        "otx_pulses": [],
        "threat_family": extract_family_from_names(threat_names),
        "severity": "unknown",
        "related_iocs": [],
    })
}

/// Enriches a hash with VirusTotal + OTX intel when keys are present. Any
/// network/parse failure degrades to [`default_result`] semantics (never
/// errors), matching v1's broad `except` handling.
pub async fn enrich(
    client: &reqwest::Client,
    vt_key: Option<&str>,
    otx_key: Option<&str>,
    hashes: &Hashes,
    threat_names: &[String],
) -> serde_json::Value {
    enrich_at(
        client,
        vt_key,
        otx_key,
        hashes,
        threat_names,
        VT_BASE_URL,
        OTX_BASE_URL,
    )
    .await
}

/// Same as [`enrich`] with explicit base URLs — the real call target
/// (`VT_BASE_URL`/`OTX_BASE_URL`) is otherwise a hardcoded constant with no
/// other injection point, so tests point this at a mock server instead of
/// the real VirusTotal/OTX APIs. `enrich` is the only production caller.
async fn enrich_at(
    client: &reqwest::Client,
    vt_key: Option<&str>,
    otx_key: Option<&str>,
    hashes: &Hashes,
    threat_names: &[String],
    vt_base_url: &str,
    otx_base_url: &str,
) -> serde_json::Value {
    // Build the result as a map so field updates need no `as_object_mut`.
    let mut map = serde_json::Map::new();
    map.insert("vt_score".to_owned(), serde_json::Value::Null);
    map.insert("otx_pulses".to_owned(), json!([]));
    map.insert(
        "threat_family".to_owned(),
        json!(extract_family_from_names(threat_names)),
    );
    map.insert("severity".to_owned(), json!("unknown"));
    map.insert("related_iocs".to_owned(), json!([]));

    let vt = match vt_key {
        Some(key) => query_virustotal(client, key, &hashes.sha256, vt_base_url).await,
        None => None,
    };
    if let Some((ratio, family)) = vt {
        map.insert("vt_score".to_owned(), json!(ratio));
        map.insert("severity".to_owned(), json!(calculate_severity(ratio)));
        if family.is_some() {
            map.insert("threat_family".to_owned(), json!(family));
        }
    }

    let otx = match otx_key {
        Some(key) => query_otx(client, key, &hashes.sha256, otx_base_url).await,
        None => None,
    };
    if let Some(pulses) = otx {
        map.insert("otx_pulses".to_owned(), pulses);
    }

    serde_json::Value::Object(map)
}

/// VirusTotal lookup → `(detection_ratio, threat_family)`. Returns `None` on
/// any non-200 or parse failure.
async fn query_virustotal(
    client: &reqwest::Client,
    api_key: &str,
    sha256: &str,
    base_url: &str,
) -> Option<(f64, Option<String>)> {
    let url = format!("{base_url}/files/{sha256}");
    let resp = client
        .get(url)
        .header("x-apikey", api_key)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    let attrs = body.get("data")?.get("attributes")?;
    let stats = attrs.get("last_analysis_stats");
    let malicious = stats
        .and_then(|s| s.get("malicious"))
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0);
    let undetected = stats
        .and_then(|s| s.get("undetected"))
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0);
    let total = malicious + undetected;
    let ratio = if total > 0.0 {
        malicious / total * 100.0
    } else {
        0.0
    };
    let family = attrs
        .get("names")
        .and_then(|n| n.as_array())
        .and_then(|a| a.first())
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    Some((ratio, family))
}

/// OTX file-pulses lookup → a compact `otx_pulses` array. `None` on failure.
async fn query_otx(
    client: &reqwest::Client,
    api_key: &str,
    sha256: &str,
    base_url: &str,
) -> Option<serde_json::Value> {
    let url = format!("{base_url}/indicators/file/{sha256}/pulses");
    let resp = client
        .get(url)
        .header("X-OTX-API-KEY", api_key)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    let results = body.get("results")?.as_array()?;
    let pulses: Vec<serde_json::Value> = results
        .iter()
        .map(|p| {
            json!({
                "id": p.get("id"),
                "name": p.get("name"),
                "tags": p.get("tags").cloned().unwrap_or_else(|| json!([])),
                "adversary": p.get("adversary"),
            })
        })
        .collect();
    Some(json!(pulses))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)] // tests fail loudly by design
mod tests {
    use super::*;

    #[test]
    fn severity_thresholds() {
        assert_eq!(calculate_severity(90.0), "critical");
        assert_eq!(calculate_severity(60.0), "high");
        assert_eq!(calculate_severity(30.0), "medium");
        assert_eq!(calculate_severity(5.0), "low");
        assert_eq!(calculate_severity(0.0), "unknown");
    }

    #[test]
    fn family_strips_platform_prefix() {
        assert_eq!(
            extract_family_from_names(&["Win32.Agent.xyz".to_owned()]),
            Some("Agent.xyz".to_owned())
        );
        assert_eq!(
            extract_family_from_names(&["EICAR_Test".to_owned()]),
            Some("EICAR_Test".to_owned())
        );
        assert_eq!(extract_family_from_names(&[]), None);
    }

    #[test]
    fn default_result_shape() {
        let v = default_result(&["Linux.Miner".to_owned()]);
        assert_eq!(v["severity"], "unknown");
        assert_eq!(v["threat_family"], "Miner");
        assert!(v["otx_pulses"].as_array().expect("array").is_empty());
        assert!(v["vt_score"].is_null());
    }

    // ── enrich() / query_virustotal / query_otx — mocked HTTP ──────────────
    //
    // `VT_BASE_URL`/`OTX_BASE_URL` are hardcoded call targets with no other
    // injection point, so these tests go through the private `enrich_at`
    // seam to point both lookups at a wiremock server instead of the real
    // internet. `enrich` itself is a one-line wrapper around `enrich_at`
    // with the real constants — not independently tested beyond that.

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn hashes() -> Hashes {
        Hashes {
            md5: "d41d8cd98f00b204e9800998ecf8427e".to_owned(),
            sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_owned(),
            sha256: "deadbeefcafe".to_owned(),
        }
    }

    #[tokio::test]
    async fn enrich_without_keys_matches_default_result() {
        let client = reqwest::Client::new();
        let got = enrich_at(
            &client,
            None,
            None,
            &hashes(),
            &[],
            "http://unused",
            "http://unused",
        )
        .await;
        assert_eq!(got, default_result(&[]));
    }

    #[tokio::test]
    async fn enrich_with_vt_success_sets_score_severity_and_raw_family() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/files/deadbeefcafe"))
            .and(header("x-apikey", "vtkey"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"attributes": {
                    "last_analysis_stats": {"malicious": 80, "undetected": 20},
                    "names": ["Win32.Foo.bar"]
                }}
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let got = enrich_at(
            &client,
            Some("vtkey"),
            None,
            &hashes(),
            &[],
            &server.uri(),
            "http://unused",
        )
        .await;
        assert_eq!(got["vt_score"], 80.0);
        assert_eq!(got["severity"], "critical");
        // VT's family is used raw — unlike `extract_family_from_names`, no
        // platform-prefix stripping is applied on this path.
        assert_eq!(got["threat_family"], "Win32.Foo.bar");
    }

    #[tokio::test]
    async fn enrich_with_vt_success_but_no_names_keeps_default_family() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/files/deadbeefcafe"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "undetected": 10}}}
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let got = enrich_at(
            &client,
            Some("vtkey"),
            None,
            &hashes(),
            &["Win32.Agent.xyz".to_owned()],
            &server.uri(),
            "http://unused",
        )
        .await;
        assert_eq!(got["vt_score"], 0.0);
        // Default family (derived from the scan's own threat_names) survives
        // because VT reported no `names`.
        assert_eq!(got["threat_family"], "Agent.xyz");
    }

    #[tokio::test]
    async fn enrich_with_vt_non_success_status_keeps_default() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/files/deadbeefcafe"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let got = enrich_at(
            &client,
            Some("vtkey"),
            None,
            &hashes(),
            &[],
            &server.uri(),
            "http://unused",
        )
        .await;
        assert!(got["vt_score"].is_null());
        assert_eq!(got["severity"], "unknown");
    }

    #[tokio::test]
    async fn enrich_with_vt_unparseable_body_keeps_default() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/files/deadbeefcafe"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let got = enrich_at(
            &client,
            Some("vtkey"),
            None,
            &hashes(),
            &[],
            &server.uri(),
            "http://unused",
        )
        .await;
        assert!(got["vt_score"].is_null());
    }

    #[tokio::test]
    async fn enrich_with_otx_success_populates_pulses() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/indicators/file/deadbeefcafe/pulses"))
            .and(header("X-OTX-API-KEY", "otxkey"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [
                    {"id": 1, "name": "Pulse A", "tags": ["t1", "t2"], "adversary": "Group X"}
                ]
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let got = enrich_at(
            &client,
            None,
            Some("otxkey"),
            &hashes(),
            &[],
            "http://unused",
            &server.uri(),
        )
        .await;
        let pulses = got["otx_pulses"].as_array().expect("array");
        assert_eq!(pulses.len(), 1);
        assert_eq!(pulses[0]["name"], "Pulse A");
        assert_eq!(pulses[0]["adversary"], "Group X");
    }

    #[tokio::test]
    async fn enrich_with_otx_missing_results_keeps_default_empty_pulses() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/indicators/file/deadbeefcafe/pulses"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let got = enrich_at(
            &client,
            None,
            Some("otxkey"),
            &hashes(),
            &[],
            "http://unused",
            &server.uri(),
        )
        .await;
        assert!(got["otx_pulses"].as_array().expect("array").is_empty());
    }

    #[tokio::test]
    async fn enrich_with_both_keys_merges_vt_and_otx() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/files/deadbeefcafe"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"attributes": {"last_analysis_stats": {"malicious": 30, "undetected": 70}}}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/indicators/file/deadbeefcafe/pulses"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": [{"id": 2, "name": "Pulse B", "tags": [], "adversary": null}]
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let got = enrich_at(
            &client,
            Some("vtkey"),
            Some("otxkey"),
            &hashes(),
            &[],
            &server.uri(),
            &server.uri(),
        )
        .await;
        assert_eq!(got["vt_score"], 30.0);
        assert_eq!(got["severity"], "medium");
        assert_eq!(got["otx_pulses"].as_array().expect("array").len(), 1);
    }
}
