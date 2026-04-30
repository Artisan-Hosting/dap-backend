//! DNS and liveness helpers for discovery.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{IpAddr, ToSocketAddrs},
    path::PathBuf,
    process::Command,
    thread,
    time::Instant,
};

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use super::{canonical_host, dedupe_strings};

#[derive(Debug, Clone)]
pub(super) struct MxRecord {
    pub(super) preference: u32,
    pub(super) exchange: String,
}

pub(super) fn query_txt_records(name: &str, zone_dump: &ZoneDump) -> Result<Vec<String>> {
    let records = dedupe_strings(dig_short(name, Some("TXT"))?);
    if !records.is_empty() {
        return Ok(records);
    }

    let records = dedupe_strings(host_short(name, "TXT")?);
    if !records.is_empty() {
        return Ok(records);
    }

    Ok(dedupe_strings(
        zone_dump.lookup(name, "TXT").cloned().unwrap_or_default(),
    ))
}

pub(super) fn query_mx_records(name: &str, zone_dump: &ZoneDump) -> Result<Vec<MxRecord>> {
    let (dig, host) = thread::scope(|scope| {
        let dig = scope.spawn(|| dig_short(name, Some("MX")));
        let host = scope.spawn(|| host_short(name, "MX"));

        let dig = dig
            .join()
            .map_err(|_| anyhow::anyhow!("dig MX worker panicked"))??;
        let host = host
            .join()
            .map_err(|_| anyhow::anyhow!("host MX worker panicked"))??;
        Ok::<_, anyhow::Error>((dig, host))
    })?;

    let mut records = Vec::new();
    for raw in dig {
        if let Some(record) = parse_mx_record(&raw) {
            records.push(record);
        }
    }

    if records.is_empty() {
        for raw in host {
            if let Some(record) = parse_mx_record(&raw) {
                records.push(record);
            }
        }
    }

    if records.is_empty() {
        if let Some(values) = zone_dump.lookup(name, "MX") {
            for raw in values {
                if let Some(record) = parse_mx_record(raw) {
                    records.push(record);
                }
            }
        }
    }

    Ok(records)
}

pub(super) fn query_dkim_records(
    name: &str,
    zone_dump: &ZoneDump,
) -> Result<Vec<(String, String)>> {
    let selector_results = thread::scope(|scope| {
        let mut handles = Vec::new();
        for selector in COMMON_DKIM_SELECTORS {
            let record_name = format!("{}._domainkey.{}", selector, name);
            handles.push(scope.spawn(move || {
                let values = query_txt_records(&record_name, zone_dump).unwrap_or_default();
                (selector.to_string(), values)
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            let (selector, values) = handle
                .join()
                .map_err(|_| anyhow::anyhow!("dkim selector worker panicked"))?;
            results.push((selector, values));
        }
        Ok::<_, anyhow::Error>(results)
    })?;

    let mut records = Vec::new();
    for (selector, values) in selector_results {
        for value in values {
            records.push((selector.clone(), value));
        }
    }
    Ok(records)
}

pub(super) fn query_cname_record(name: &str, zone_dump: &ZoneDump) -> Result<Option<String>> {
    let records = dig_short(name, Some("CNAME"))?;
    if let Some(record) = records.into_iter().next() {
        return Ok(Some(record));
    }

    if let Some(record) = host_short(name, "CNAME")?.into_iter().next() {
        return Ok(Some(record));
    }

    Ok(zone_dump
        .lookup(name, "CNAME")
        .and_then(|values| values.first().cloned()))
}

pub(super) fn query_address_records(name: &str, zone_dump: &ZoneDump) -> Result<Vec<String>> {
    let (a_records, aaaa_records) = thread::scope(|scope| {
        let a = scope.spawn(|| dig_short(name, Some("A")));
        let aaaa = scope.spawn(|| dig_short(name, Some("AAAA")));
        let a = a
            .join()
            .map_err(|_| anyhow::anyhow!("A record worker panicked"))??;
        let aaaa = aaaa
            .join()
            .map_err(|_| anyhow::anyhow!("AAAA record worker panicked"))??;
        Ok::<_, anyhow::Error>((a, aaaa))
    })?;

    let mut addresses = Vec::new();
    addresses.extend(a_records);
    addresses.extend(aaaa_records);
    let addresses = normalize_ip_addresses(addresses);
    if !addresses.is_empty() {
        return Ok(addresses);
    }

    let addresses = system_lookup_ip_addresses(name);
    if !addresses.is_empty() {
        return Ok(addresses);
    }

    let mut fallback = Vec::new();
    if let Some(values) = zone_dump.lookup(name, "A") {
        fallback.extend(values.clone());
    }
    if let Some(values) = zone_dump.lookup(name, "AAAA") {
        fallback.extend(values.clone());
    }
    Ok(normalize_ip_addresses(fallback))
}

pub(super) enum HostLiveness {
    Alive,
    Dead(String),
}

pub(super) fn check_host_liveness(host: &str) -> HostLiveness {
    debug!(host = %host, "starting host liveness probe");
    let (https, http, ping) = thread::scope(|scope| {
        let https = scope.spawn(|| probe_https(host));
        let http = scope.spawn(|| probe_http(host));
        let ping = scope.spawn(|| probe_ping(host));

        let https = https
            .join()
            .map_err(|_| anyhow::anyhow!("https probe worker panicked"))?;
        let http = http
            .join()
            .map_err(|_| anyhow::anyhow!("http probe worker panicked"))?;
        let ping = ping
            .join()
            .map_err(|_| anyhow::anyhow!("ping probe worker panicked"))?;
        Ok::<_, anyhow::Error>((https, http, ping))
    })
    .map(|(https, http, ping)| (https, http, ping))
    .unwrap_or_else(|err| {
        debug!(host = %host, error = %err, "liveness probe worker failed");
        (
            ProbeResult::Failure(err.to_string()),
            ProbeResult::Failure(err.to_string()),
            ProbeResult::Failure(err.to_string()),
        )
    });

    let mut reasons = Vec::new();
    for (scheme, result) in [("https", https), ("http", http), ("ping", ping)] {
        match result {
            ProbeResult::Success => {
                debug!(host = %host, probe = scheme, "liveness probe succeeded");
                return HostLiveness::Alive;
            }
            ProbeResult::Failure(reason) => reasons.push(reason),
        }
    }

    debug!(host = %host, reason = %reasons.join(" | "), "host classified as dead");
    HostLiveness::Dead(reasons.join(" | "))
}

pub(super) fn query_dns_wildcard(domain: &str) -> Vec<String> {
    let mut hosts = BTreeSet::new();

    let common_subs = [
        "www",
        "mail",
        "smtp",
        "pop",
        "imap",
        "ftp",
        "admin",
        "login",
        "api",
        "app",
        "dev",
        "staging",
        "test",
        "portal",
        "dashboard",
        "blog",
        "shop",
        "store",
        "support",
        "help",
        "docs",
        "api",
        "cdn",
        "static",
    ];

    for sub in common_subs {
        let host = format!("{}.{}", sub, domain);
        if dig_short(&host, Some("A")).is_ok_and(|r| !r.is_empty()) {
            hosts.insert(canonical_host(&host));
        }
    }

    info!(domain = %domain, count = hosts.len(), "discovered subdomains from DNS wildcard");
    hosts.into_iter().collect()
}

#[derive(Debug, Default)]
pub(super) struct ZoneDump {
    hosts: BTreeSet<String>,
    records: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

impl ZoneDump {
    pub(super) fn hosts(&self) -> &BTreeSet<String> {
        &self.hosts
    }

    pub(super) fn lookup(&self, name: &str, record_type: &str) -> Option<&Vec<String>> {
        let key = canonical_host(name);
        self.records
            .get(&key)
            .and_then(|types| types.get(&record_type.to_uppercase()))
    }

    fn insert(&mut self, name: String, record_type: &str, value: String) {
        self.hosts.insert(name.clone());
        self.records
            .entry(name)
            .or_insert_with(BTreeMap::new)
            .entry(record_type.to_uppercase())
            .or_insert_with(Vec::new)
            .push(value);
    }
}

fn parse_mx_record(raw: &str) -> Option<MxRecord> {
    let mut parts = raw.split_whitespace();
    let preference = parts.next()?.parse::<u32>().ok()?;
    let exchange = canonical_host(parts.next()?);
    Some(MxRecord {
        preference,
        exchange,
    })
}

pub(super) fn probe_https(host: &str) -> ProbeResult {
    probe_curl(host, true)
}

pub(super) fn probe_http(host: &str) -> ProbeResult {
    probe_curl(host, false)
}

fn probe_curl(host: &str, https: bool) -> ProbeResult {
    let scheme = if https { "https" } else { "http" };
    let url = format!("{scheme}://{host}/");
    let mut command = Command::new("curl");
    let started_at = Instant::now();
    command
        .arg("-I")
        .arg("--max-time")
        .arg("3")
        .arg("--connect-timeout")
        .arg("2")
        .arg("--silent")
        .arg("--output")
        .arg("/dev/null")
        .arg("--show-error")
        .arg("--insecure")
        .arg(url);

    run_probe(command, &format!("curl {scheme} {host}"), Some(started_at))
}

fn probe_ping(host: &str) -> ProbeResult {
    let mut command = Command::new("ping");
    command.arg("-c").arg("1").arg("-W").arg("1").arg(host);
    run_probe(command, &format!("ping {host}"), Some(Instant::now()))
}

fn run_probe(mut command: Command, description: &str, started_at: Option<Instant>) -> ProbeResult {
    match command.output() {
        Ok(output) if output.status.success() => {
            if let Some(started_at) = started_at {
                debug!(
                    probe = %description,
                    elapsed_ms = started_at.elapsed().as_millis(),
                    "probe succeeded"
                );
            }
            ProbeResult::Success
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if let Some(started_at) = started_at {
                debug!(
                    probe = %description,
                    elapsed_ms = started_at.elapsed().as_millis(),
                    status = ?output.status.code(),
                    stderr = %stderr.trim(),
                    "probe failed"
                );
            }
            ProbeResult::Failure(format!(
                "{description} failed (status {:?}): {}",
                output.status.code(),
                stderr.trim()
            ))
        }
        Err(err) => {
            if let Some(started_at) = started_at {
                debug!(
                    probe = %description,
                    elapsed_ms = started_at.elapsed().as_millis(),
                    error = %err,
                    "probe spawn error"
                );
            }
            ProbeResult::Failure(format!("{description} spawn error: {err}"))
        }
    }
}

fn dig_short(name: &str, record_type: Option<&str>) -> Result<Vec<String>> {
    let mut args = vec![
        "@1.1.1.1".to_string(),
        "+timeout=2".to_string(),
        "+tries=2".to_string(),
        "+short".to_string(),
        "+nocmd".to_string(),
        name.to_string(),
    ];

    if let Some(rt) = record_type {
        args.push(rt.to_string());
    }

    let output = Command::new("dig")
        .args(&args)
        .output()
        .with_context(|| format!("failed to invoke dig for {}", name))?;

    if !output.status.success() {
        debug!(
            command = "dig",
            host = name,
            record_type = ?record_type,
            status = %output.status,
            "dig command returned non-zero status"
        );
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') {
            continue;
        }
        let without_dot = trimmed.trim_end_matches('.');
        let unquoted = without_dot.trim_matches('"').to_string();
        if unquoted.is_empty() {
            continue;
        }
        lines.push(unquoted.to_lowercase());
    }
    Ok(lines)
}

fn host_short(name: &str, record_type: &str) -> Result<Vec<String>> {
    let output = Command::new("host")
        .arg("-W")
        .arg("2")
        .arg("-t")
        .arg(record_type.to_ascii_lowercase())
        .arg(name)
        .output()
        .with_context(|| format!("failed to invoke host for {} {}", record_type, name))?;

    if !output.status.success() {
        debug!(
            command = "host",
            host = name,
            record_type,
            status = %output.status,
            "host command returned non-zero status"
        );
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_host_output(&stdout, record_type))
}

fn parse_host_output(stdout: &str, record_type: &str) -> Vec<String> {
    let record_type = record_type.to_ascii_uppercase();
    stdout
        .lines()
        .filter_map(|line| parse_host_output_line(line.trim(), &record_type))
        .collect()
}

fn parse_host_output_line(line: &str, record_type: &str) -> Option<String> {
    match record_type {
        "TXT" => parse_host_txt_line(line),
        "MX" => parse_host_mx_line(line),
        "CNAME" => parse_host_cname_line(line),
        _ => None,
    }
}

pub(super) fn parse_host_txt_line(line: &str) -> Option<String> {
    let mut values = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes {
                    values.push(current.clone());
                    current.clear();
                    in_quotes = false;
                } else {
                    in_quotes = true;
                }
            }
            '\\' if in_quotes => {
                let mut octal = String::new();
                for _ in 0..3 {
                    let Some(next) = chars.peek().copied() else {
                        break;
                    };
                    if !matches!(next, '0'..='7') {
                        break;
                    }
                    octal.push(next);
                    let _ = chars.next();
                }

                if octal.len() == 3 {
                    if let Ok(value) = u8::from_str_radix(&octal, 8) {
                        current.push(value as char);
                    }
                } else if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            _ if in_quotes => current.push(ch),
            _ => {}
        }
    }

    if values.is_empty() {
        None
    } else {
        Some(
            values
                .join("")
                .chars()
                .map(|ch| if ch.is_control() { ' ' } else { ch })
                .collect::<String>()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase(),
        )
    }
}

pub(super) fn parse_host_mx_line(line: &str) -> Option<String> {
    let suffix = line.split(" mail is handled by ").nth(1)?;
    let mut parts = suffix.split_whitespace();
    let preference = parts.next()?;
    let exchange = canonical_host(parts.next()?);
    Some(format!("{preference} {exchange}"))
}

pub(super) fn parse_host_cname_line(line: &str) -> Option<String> {
    let target = line
        .split(" is an alias for ")
        .nth(1)
        .or_else(|| line.split(" is a nickname for ").nth(1))?;
    Some(canonical_host(target.trim_end_matches('.')))
}

fn normalize_ip_addresses(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter_map(|value| value.parse::<IpAddr>().ok().map(|ip| ip.to_string()))
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn system_lookup_ip_addresses(name: &str) -> Vec<String> {
    let Ok(addresses) = (name, 0).to_socket_addrs() else {
        debug!(host = name, "system resolver returned no socket addresses");
        return Vec::new();
    };

    normalize_ip_addresses(addresses.map(|address| address.ip().to_string()).collect())
}

pub(super) fn ip_family(value: &str) -> Option<&'static str> {
    match value.parse::<IpAddr>().ok()? {
        IpAddr::V4(_) => Some("ipv4"),
        IpAddr::V6(_) => Some("ipv6"),
    }
}

pub(super) fn load_zone_dump(domain: &str) -> ZoneDump {
    let mut dump = ZoneDump::default();
    let path = PathBuf::from(format!("{}.txt", domain));
    if !path.exists() {
        return dump;
    }

    let contents = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(err) => {
            warn!(
                dump = %path.display(),
                error = %err,
                "failed to read zone dump; skipping"
            );
            return dump;
        }
    };

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('$') {
            continue;
        }

        let without_comment = trimmed.splitn(2, ';').next().unwrap().trim();
        let tokens: Vec<&str> = without_comment.split_whitespace().collect();
        if tokens.len() < 3 {
            continue;
        }

        let mut name = tokens[0];
        if name.eq("@") {
            name = domain;
        }

        let mut idx = 1;
        let mut record_type: Option<&str> = None;
        while idx < tokens.len() {
            let token = tokens[idx];
            let upper = token.to_uppercase();
            if upper == "IN" || upper.chars().all(|c| c.is_ascii_digit()) {
                idx += 1;
                continue;
            }
            if matches!(upper.as_str(), "A" | "AAAA" | "CNAME" | "TXT" | "MX") {
                record_type = Some(tokens[idx]);
                idx += 1;
                break;
            }
            idx += 1;
        }

        let record_type = match record_type {
            Some(rt) => rt,
            None => continue,
        };

        if idx >= tokens.len() {
            continue;
        }

        let value = tokens[idx..].join(" ");
        let value = value
            .trim()
            .trim_matches('"')
            .trim_end_matches('.')
            .to_string();
        if value.is_empty() {
            continue;
        }

        if !matches!(
            record_type.to_uppercase().as_str(),
            "A" | "AAAA" | "CNAME" | "TXT" | "MX"
        ) {
            continue;
        }

        let host = normalize_zone_name(name, domain);
        dump.insert(host, record_type, canonical_value(record_type, value));
    }

    dump
}

fn normalize_zone_name(name: &str, domain: &str) -> String {
    if name == "@" {
        return domain.to_string();
    }
    canonical_host(name)
}

fn canonical_value(record_type: &str, value: String) -> String {
    match record_type.to_uppercase().as_str() {
        "CNAME" => canonical_host(&value),
        _ => value,
    }
}

#[derive(Debug)]
pub(super) enum ProbeResult {
    Success,
    Failure(String),
}

const COMMON_DKIM_SELECTORS: &[&str] = &[
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "k2",
    "s1",
    "s2",
];
