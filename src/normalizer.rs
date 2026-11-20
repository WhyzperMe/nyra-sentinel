//! Parsers never infer attacker direction from the syslog transport peer.
use serde::Serialize;
use serde_json::{json, Value};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize)]
pub struct SecurityEvent {
    pub source: String,
    pub event_ts: Option<String>,
    pub category: String,
    pub action: Option<String>,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub source_port: Option<i64>,
    pub destination_port: Option<i64>,
    pub protocol: Option<String>,
    pub interface: Option<String>,
    pub direction: Option<String>,
    pub rule_tracker: Option<String>,
    pub domain: Option<String>,
    pub dns_qtype: Option<String>,
    pub details_json: String,
}

impl SecurityEvent {
    fn new(source: &str, category: &str, time: Option<String>) -> Self {
        Self {
            source: source.to_owned(),
            event_ts: time,
            category: category.to_owned(),
            action: None,
            source_ip: None,
            destination_ip: None,
            source_port: None,
            destination_port: None,
            protocol: None,
            interface: None,
            direction: None,
            rule_tracker: None,
            domain: None,
            dns_qtype: None,
            details_json: "{}".to_owned(),
        }
    }
}

fn ip(text: &str) -> Option<String> {
    text.parse::<IpAddr>().ok().map(|v| v.to_string())
}
fn field(v: &Value, key: &str) -> Option<String> {
    v.get(key)?.as_str().map(str::to_owned)
}
fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

/// Official OPNsense filterlog CSV layout. 'malformed' is not silently promoted to evidence.
pub fn filterlog(line: &str, event_ts: Option<String>) -> Result<SecurityEvent, &'static str> {
    // Do not split on syslog header; Vector already supplied `.message`.
    let parts: Vec<&str> = line.split(',').collect();
    if parts.len() < 17 {
        return Err("short filterlog record");
    }
    if parts[4].is_empty() {
        return Err("missing interface");
    }
    if !matches!(parts[6], "pass" | "block" | "reject" | "match") {
        return Err("unsupported firewall action");
    }
    if !matches!(parts[7], "in" | "out") {
        return Err("invalid firewall direction");
    }
    let (p_name, p_num, src_index, dst_index, port_index) = match parts[8] {
        "4" if parts.len() >= 20 => (16, 15, 18, 19, 20),
        "6" if parts.len() >= 17 => (12, 13, 15, 16, 17),
        _ => return Err("unsupported or incomplete IP version"),
    };
    let src = ip(parts[src_index]).ok_or("invalid source IP")?;
    let dst = ip(parts[dst_index]).ok_or("invalid destination IP")?;
    let version = match parts[8] {
        "4" => 4,
        "6" => 6,
        _ => unreachable!(),
    };
    let want_v4 = version == 4;
    if src
        .parse::<IpAddr>()
        .ok()
        .is_none_or(|a| a.is_ipv4() != want_v4)
        || dst
            .parse::<IpAddr>()
            .ok()
            .is_none_or(|a| a.is_ipv4() != want_v4)
    {
        return Err("IP address/version mismatch");
    }
    let proto = parts[p_name].to_ascii_lowercase();
    let expected = parts[p_num]
        .parse::<u8>()
        .map_err(|_| "bad protocol number")?;
    let mut e = SecurityEvent::new("opnsense-syslog", "firewall.filterlog", event_ts);
    e.action = Some(parts[6].to_owned());
    e.source_ip = Some(src);
    e.destination_ip = Some(dst);
    e.protocol = Some(if proto.is_empty() {
        expected.to_string()
    } else {
        proto
    });
    e.interface = nonempty(parts[4]);
    e.direction = Some(parts[7].to_owned());
    e.rule_tracker = nonempty(parts[3]);
    if matches!(expected, 6 | 17) {
        if parts.len() < port_index + 2 {
            return Err("missing TCP/UDP ports");
        }
        e.source_port = Some(
            parts[port_index]
                .parse::<u16>()
                .map_err(|_| "bad source port")? as i64,
        );
        e.destination_port = Some(
            parts[port_index + 1]
                .parse::<u16>()
                .map_err(|_| "bad destination port")? as i64,
        );
    }
    e.details_json = json!({"rule_number": parts[0], "subrule": parts[1], "anchor": parts[2],
        "reason": parts[5], "ip_version": version, "protocol_number": expected})
    .to_string();
    Ok(e)
}

pub fn adguard(v: &Value) -> Result<SecurityEvent, &'static str> {
    let time = field(v, "time").ok_or("DNS entry missing time")?;
    let ts = time
        .parse::<jiff::Timestamp>()
        .map_err(|_| "invalid DNS time")?
        .to_string();
    let question = v.get("question").ok_or("DNS entry missing question")?;
    let domain = field(question, "name").ok_or("DNS entry missing domain")?;
    if domain.is_empty() || domain.len() > 253 || domain.chars().any(char::is_control) {
        return Err("invalid DNS domain");
    }
    let reason = field(v, "reason").unwrap_or_default();
    let mut e = SecurityEvent::new("adguard-querylog", "dns.query", Some(ts));
    e.action = Some(
        if reason.starts_with("Filtered") && !matches!(reason.as_str(), "FilteredSafeSearch") {
            "filtered"
        } else {
            "observed"
        }
        .to_owned(),
    );
    e.source_ip = field(v, "client").and_then(|s| ip(&s));
    e.domain = Some(domain.to_ascii_lowercase());
    e.dns_qtype = field(question, "type").or_else(|| {
        question
            .get("type")
            .and_then(Value::as_u64)
            .map(|n| n.to_string())
    });
    e.protocol = Some("dns".to_owned());
    e.details_json = json!({"reason": reason, "status": v.get("status"),
        "response_status": v.get("response_status"), "client": v.get("client")})
    .to_string();
    Ok(e)
}

pub fn crowdsec(v: &Value, state: &str) -> SecurityEvent {
    let mut e = SecurityEvent::new(
        "crowdsec-decision",
        "crowdsec.decision",
        Some(jiff::Timestamp::now().to_string()),
    );
    e.action = Some(state.to_owned());
    if v.get("scope")
        .and_then(Value::as_str)
        .is_some_and(|s| s.eq_ignore_ascii_case("ip"))
    {
        e.source_ip = field(v, "value").and_then(|s| ip(&s));
    }
    e.details_json =
        json!({"scope": v.get("scope"), "value": v.get("value"), "type": v.get("type"),
        "scenario": v.get("scenario"), "origin": v.get("origin"), "decision_state": state})
        .to_string();
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv4_tcp() {
        let line = "85,,,9f96d956119c25145fc2ce221237f3a5,igb0,match,block,in,4,0x0,,63,11771,0,DF,6,tcp,60,10.13.37.156,193.0.6.135,43802,443,0,S,1404651214,,64240,,mss";
        let e = filterlog(line, None).unwrap();
        assert_eq!(e.source_ip.as_deref(), Some("10.13.37.156"));
        assert_eq!(e.destination_port, Some(443));
        assert_eq!(e.direction.as_deref(), Some("in"));
        assert_eq!(e.action.as_deref(), Some("block"));
    }
    #[test]
    fn ipv6_udp() {
        let line = "1,,,rule42,igb1,match,pass,out,6,0x00,0,64,udp,17,70,2001:db8::a,2001:db8::b,5353,53,24";
        let e = filterlog(line, None).unwrap();
        assert_eq!(e.source_port, Some(5353));
        assert_eq!(e.destination_ip.as_deref(), Some("2001:db8::b"));
    }
    #[test]
    fn truncated_and_invalid_never_panic() {
        assert!(filterlog("1,2,3", None).is_err());
        assert!(filterlog(
            "1,,,track,igb0,x,pass,in,4,a,b,c,d,e,f,6,tcp,60,bad,8.8.8.8,1,2",
            None
        )
        .is_err());
    }
    #[test]
    fn dns_blocked_and_not_fake_ip() {
        let value = json!({"time":"2026-11-20T19:05:00Z","client":"host.local","question":{"name":"bad.example.","type":"A"},"reason":"FilteredBlackList"});
        let e = adguard(&value).unwrap();
        assert_eq!(e.source_ip, None);
        assert_eq!(e.action.as_deref(), Some("filtered"));
    }
}
