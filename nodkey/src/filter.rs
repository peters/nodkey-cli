//! The clean-up filter, from the `filter` object of `cleanup_logins` or the command line flags.

use nodkey_proto::CleanupFilter;
use serde_json::{Map, Value};

/// The `filter` argument of `cleanup_logins`. Unknown keys are refused (a typo must not widen
/// the filter by being ignored); dates are Unix seconds or `YYYY-MM-DD` (midnight UTC).
pub fn cleanup_filter(args: &Map<String, Value>) -> Result<CleanupFilter, String> {
    let obj = match args.get("filter") {
        Some(Value::Object(o)) => o,
        None | Some(Value::Null) => {
            return Err("filter is required: an object with at least one criterion, e.g. {\"ip_only\": true}".into());
        }
        Some(_) => return Err("filter must be an object".into()),
    };
    let mut f = CleanupFilter::default();
    for (key, value) in obj {
        match key.as_str() {
            "query" | "username" | "domain" | "group" => {
                let text = match value {
                    Value::Null => None,
                    Value::String(s) if s.trim().is_empty() => None,
                    Value::String(s) if s.chars().count() > 200 => {
                        return Err(format!("filter.{key} is too long"));
                    }
                    Value::String(s) => Some(s.trim().to_owned()),
                    _ => return Err(format!("filter.{key} must be a string")),
                };
                match key.as_str() {
                    "query" => f.query = text,
                    "username" => f.username = text,
                    "group" => f.group = text,
                    _ => f.domain = text,
                }
            }
            "ip_only" | "never_used" => {
                let flag = match value {
                    Value::Null => None,
                    Value::Bool(b) => Some(*b),
                    _ => return Err(format!("filter.{key} must be true or false")),
                };
                if key == "ip_only" {
                    f.ip_only = flag;
                } else {
                    f.never_used = flag;
                }
            }
            "last_used_before" | "added_before" | "password_changed_before" => {
                let time = match value {
                    Value::Null => None,
                    Value::Number(n) => Some(n.as_u64().ok_or_else(|| {
                        format!("filter.{key} must be a positive Unix time in seconds")
                    })?),
                    Value::String(s) => Some(parse_date(s).ok_or_else(|| {
                        format!("filter.{key} must be Unix seconds or a date like 2024-01-31")
                    })?),
                    _ => return Err(format!("filter.{key} must be Unix seconds or a date")),
                };
                match key.as_str() {
                    "last_used_before" => f.last_used_before = time,
                    "added_before" => f.added_before = time,
                    _ => f.password_changed_before = time,
                }
            }
            other => {
                return Err(format!(
                    "filter.{other} is not a known criterion (use query, username, domain, ip_only, \
                     last_used_before, added_before, password_changed_before, never_used)"
                ));
            }
        }
    }
    if f.is_empty() {
        return Err(
            "filter needs at least one criterion (for example ip_only: true or a username); an empty \
             filter would match every saved login and is refused"
                .into(),
        );
    }
    Ok(f)
}

/// `YYYY-MM-DD` as Unix seconds at midnight UTC.
pub fn parse_date(s: &str) -> Option<u64> {
    let mut parts = s.trim().splitn(3, '-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cleanup_filter_arguments() {
        let parse = |v: Value| cleanup_filter(v.as_object().unwrap());
        let f =
            parse(json!({"filter": {"ip_only": true, "username": " alex@example.com "}})).unwrap();
        assert_eq!(f.ip_only, Some(true));
        assert_eq!(f.username.as_deref(), Some("alex@example.com"));
        let f = parse(
            json!({"filter": {"last_used_before": "2024-01-01", "added_before": 1_700_000_000}}),
        )
        .unwrap();
        assert_eq!(f.last_used_before, Some(1_704_067_200));
        assert_eq!(f.added_before, Some(1_700_000_000));
        for bad in [
            json!({}),
            json!({"filter": {}}),
            json!({"filter": {"ip_only": false, "query": "  "}}),
            json!({"filter": "ip"}),
            json!({"filter": {"ipOnly": true}}),
            json!({"filter": {"ip_only": "yes"}}),
            json!({"filter": {"added_before": "last year"}}),
            json!({"filter": {"added_before": -5}}),
        ] {
            assert!(parse(bad.clone()).is_err(), "{bad}");
        }
        assert!(
            parse(json!({"filter": {}}))
                .unwrap_err()
                .contains("at least one")
        );
        assert_eq!(parse_date("1970-01-01"), Some(0));
        assert_eq!(parse_date("2026-10-10"), Some(1_791_590_400));
        assert_eq!(parse_date("2026-13-01"), None);
    }
}
