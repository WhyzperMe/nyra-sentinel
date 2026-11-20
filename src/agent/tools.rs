//! LLM receives only this immutable allowlist. Server repeats policy checks independently.
use serde_json::{json, Value};

pub const TOOLS: &[&str] = &[
    "search_events",
    "get_event_details",
    "get_ip_history",
    "get_domain_history",
    "get_dns_activity",
    "get_firewall_activity",
    "get_crowdsec_decisions",
    "get_asset_profile",
    "get_source_health",
    "correlate_events",
    "get_network_baseline",
    "get_incident",
    "get_detections",
];

pub fn validate(name: &str, args: &Value) -> Result<(), String> {
    if !TOOLS.contains(&name) {
        return Err("not an approved read-only tool".into());
    }
    if !args.is_object() {
        return Err("tool arguments must be a JSON object".into());
    }
    let object = args.as_object().ok_or("tool arguments malformed")?;
    if object.len() > 7 {
        return Err("too many tool arguments".into());
    }
    for (key, value) in object {
        match key.as_str() {
            "ip" => {
                if !value
                    .as_str()
                    .is_some_and(|s| s.parse::<std::net::IpAddr>().is_ok())
                {
                    return Err("invalid IP".into());
                }
            }
            "domain" => {
                if !value.as_str().is_some_and(|s| {
                    s.len() <= 253
                        && !s.is_empty()
                        && s.is_ascii()
                        && s.split('.').all(|part| {
                            !part.is_empty()
                                && part.len() <= 63
                                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                                && !part.starts_with('-')
                                && !part.ends_with('-')
                        })
                }) {
                    return Err("invalid domain".into());
                }
            }
            "event_id" | "incident_id" => {
                if !value
                    .as_str()
                    .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok())
                {
                    return Err("invalid UUID".into());
                }
            }
            "source" => {
                if !value.as_str().is_some_and(|s| {
                    !s.is_empty()
                        && s.len() <= 64
                        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                }) {
                    return Err("invalid source".into());
                }
            }
            "hours" => {
                if !value.as_i64().is_some_and(|n| (1..=168).contains(&n)) {
                    return Err("invalid hours".into());
                }
            }
            "limit" => {
                if !value.as_i64().is_some_and(|n| (1..=50).contains(&n)) {
                    return Err("invalid limit".into());
                }
            }
            _ => return Err("unknown tool argument".into()),
        }
    }
    let required = match name {
        "get_ip_history"
        | "get_dns_activity"
        | "get_firewall_activity"
        | "get_asset_profile"
        | "correlate_events"
        | "get_network_baseline" => "ip",
        "get_domain_history" => "domain",
        "get_event_details" => "event_id",
        "get_incident" => "incident_id",
        "search_events" => {
            if object.contains_key("ip") {
                "ip"
            } else {
                "domain"
            }
        }
        _ => "",
    };
    if !required.is_empty() && !object.contains_key(required) {
        return Err("tool subject missing".into());
    }
    Ok(())
}

pub fn definitions() -> Value {
    let ip = json!({"type":"string","description":"Valid IPv4 or IPv6 address"});
    let domain = json!({"type":"string","description":"DNS domain name"});
    let mut all = Vec::new();
    for name in TOOLS {
        let (description, required): (&str, Vec<&str>) = match *name {
            "search_events" => (
                "Search bounded normalized events by ip or domain; at least one filter",
                vec![],
            ),
            "get_event_details" => (
                "Get one normalized event by UUID, never raw payload",
                vec!["event_id"],
            ),
            "get_ip_history" => ("Recent observed security events for an IP", vec!["ip"]),
            "get_domain_history" => ("Recent DNS activity for one domain", vec!["domain"]),
            "get_dns_activity" => ("Recent DNS queries associated with client IP", vec!["ip"]),
            "get_firewall_activity" => ("Recent PF filterlog observations for IP", vec!["ip"]),
            "get_crowdsec_decisions" => ("Active CrowdSec mitigations; optional exact IP", vec![]),
            "get_asset_profile" => (
                "Stored asset counters for client IP, not validated identity",
                vec!["ip"],
            ),
            "get_source_health" => (
                "Telemetry source freshness and failures; optional source name",
                vec![],
            ),
            "correlate_events" => (
                "Observe bounded timeline of events involving IP",
                vec!["ip"],
            ),
            "get_network_baseline" => ("Read historical per-client DNS volume buckets", vec!["ip"]),
            "get_incident" => ("Lookup deterministic incident by UUID", vec!["incident_id"]),
            _ => ("Read deterministic detection summaries", vec![]),
        };
        all.push(json!({"type":"function","function":{"name":name,"description":description,
            "parameters":{"type":"object","properties":{
                "ip":ip,"domain":domain,"event_id":{"type":"string"},"incident_id":{"type":"string"},
                "source":{"type":"string"},"hours":{"type":"integer","minimum":1,"maximum":168},
                "limit":{"type":"integer","minimum":1,"maximum":50}},
                "required":required,"additionalProperties":false}}}));
    }
    Value::Array(all)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malicious_tools_denied() {
        assert!(validate("execute_shell", &json!({"ip":"192.0.2.1"})).is_err());
        assert!(validate(
            "get_ip_history",
            &json!({"ip":"192.0.2.1","sql":"DROP TABLE"})
        )
        .is_err());
        assert!(validate("get_ip_history", &json!({"ip":"192.0.2.1","hours":169})).is_err());
        assert!(validate("get_ip_history", &json!({"ip":"192.0.2.1","hours":24})).is_ok());
    }
    #[test]
    fn definitions_are_unique() {
        let defs = definitions();
        assert_eq!(defs.as_array().unwrap().len(), TOOLS.len());
    }
}
