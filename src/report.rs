//! HTML report bundle generation.
//!
//! The JSON artifacts remain the source of truth, but this module turns a run
//! into a browsable set of pages for large domains.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::{
    discovery::{DeadHost, SiteProfile},
    tests::{TestOutput, TestSeverity, TestStatus},
};

const DEFAULT_CSS: &str = r#"
:root {
  color-scheme: dark;
  --bg: #0b1020;
  --panel: #10182e;
  --panel-2: #16213d;
  --text: #e9eefc;
  --muted: #9ea8c7;
  --line: rgba(255,255,255,.08);
  --pass: #49d17d;
  --warn: #f4c95d;
  --fail: #ff7d7d;
  --error: #ff6161;
  --skip: #8f9bbb;
  --info: #66b3ff;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: linear-gradient(180deg, #0b1020 0%, #0d1326 100%);
  color: var(--text);
  font: 14px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
a { color: #9dc1ff; text-decoration: none; }
a:hover { text-decoration: underline; }
.wrap { max-width: 1280px; margin: 0 auto; padding: 32px 20px 64px; }
.hero { display: flex; justify-content: space-between; gap: 24px; align-items: end; margin-bottom: 24px; }
.hero h1 { margin: 0 0 6px; font-size: 34px; line-height: 1.1; }
.hero p, .muted { color: var(--muted); margin: 0; }
.grid { display: grid; gap: 16px; }
.grid.cols-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
.panel {
  background: rgba(16,24,46,.92);
  border: 1px solid var(--line);
  border-radius: 18px;
  padding: 18px;
  box-shadow: 0 18px 48px rgba(0,0,0,.24);
}
.panel h2, .panel h3 { margin-top: 0; }
.stat { padding: 16px; background: var(--panel-2); border: 1px solid var(--line); border-radius: 16px; }
.stat .k { display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
.stat .v { font-size: 28px; font-weight: 700; }
.chips { display: flex; gap: 8px; flex-wrap: wrap; }
.chip { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 999px; background: rgba(255,255,255,.06); border: 1px solid var(--line); font-size: 12px; }
.chip.pass { color: var(--pass); }
.chip.warn { color: var(--warn); }
.chip.fail { color: var(--fail); }
.chip.error { color: var(--error); }
.chip.skipped { color: var(--skip); }
.chip.info { color: var(--info); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; background: rgba(255,255,255,.08); color: var(--text); font-size: 12px; }
.section { margin-top: 22px; }
.card-list { display: grid; gap: 12px; }
.card { padding: 14px; border: 1px solid var(--line); border-radius: 16px; background: rgba(255,255,255,.03); }
.card h4 { margin: 0 0 8px; font-size: 16px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 10px 8px; border-bottom: 1px solid var(--line); vertical-align: top; text-align: left; }
th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
pre { margin: 0; white-space: pre-wrap; word-break: break-word; }
details { margin-top: 10px; }
summary { cursor: pointer; color: var(--muted); }
.footer-links { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 16px; }
@media (max-width: 900px) {
  .grid.cols-4 { grid-template-columns: 1fr; }
  .hero { flex-direction: column; align-items: start; }
}
"#;

/// Render the report bundle for a completed run.
pub fn render_report(
    root: &Path,
    results_dir: &Path,
    report_formats: &[String],
    css_override: Option<&Path>,
) -> Result<Option<PathBuf>> {
    if !report_formats
        .iter()
        .any(|format| format.eq_ignore_ascii_case("html"))
    {
        return Ok(None);
    }

    let report_dir = root.join("report");
    let assets_dir = report_dir.join("assets");
    let hosts_dir = report_dir.join("hosts");
    fs::create_dir_all(&assets_dir)?;
    fs::create_dir_all(&hosts_dir)?;

    let data = ReportData::load(results_dir)?;
    write_css(&assets_dir.join("report.css"), css_override)?;
    write_index(&report_dir.join("index.html"), &data)?;
    write_dead_page(&report_dir.join("dead.html"), &data)?;

    for host in &data.active_hosts {
        write_host_page(
            &hosts_dir.join(format!("{}.html", slugify(&host.host))),
            host,
        )?;
    }

    Ok(Some(report_dir.join("index.html")))
}

fn write_css(path: &Path, override_path: Option<&Path>) -> Result<()> {
    if let Some(path_override) = override_path {
        if path_override.exists() {
            fs::copy(path_override, path)
                .with_context(|| format!("failed to copy CSS from {}", path_override.display()))?;
            return Ok(());
        }
    }

    fs::write(path, DEFAULT_CSS)?;
    Ok(())
}

fn write_index(path: &Path, data: &ReportData) -> Result<()> {
    let mut body = String::new();
    body.push_str("<div class=\"wrap\">");
    body.push_str(&hero(
        &format!("{} · sweep report", data.domain),
        "Active hosts are rendered as HTML pages. Dead or unavailable hosts are moved to a separate section.",
    ));
    body.push_str(&stats_grid(&[
        ("Active hosts", data.active_hosts.len().to_string()),
        ("Dead / unavailable", data.dead.len().to_string()),
        ("Profiles", data.site_profiles.len().to_string()),
        ("Active tests", data.active_test_count.to_string()),
    ]));
    body.push_str(&section_start("Site Profiles"));
    body.push_str("<div class=\"card-list\">");
    for profile in &data.site_profiles {
        body.push_str(&profile_card(profile));
    }
    body.push_str("</div>");
    body.push_str(&section_end());

    body.push_str(&section_start("Active Hosts"));
    body.push_str("<div class=\"card-list\">");
    for host in &data.active_hosts {
        body.push_str(&host_card(host));
    }
    body.push_str("</div>");
    body.push_str(&section_end());

    body.push_str(&section_start("Dead / Unavailable"));
    body.push_str("<div class=\"card-list\">");
    for dead in &data.dead {
        body.push_str(&dead_card(dead));
    }
    body.push_str("</div>");
    body.push_str(&section_end());

    body.push_str("<div class=\"footer-links\"><a href=\"dead.html\">Open dead page</a></div>");
    body.push_str("</div>");

    fs::write(path, page("Index", &body, "assets/report.css"))?;
    Ok(())
}

fn write_dead_page(path: &Path, data: &ReportData) -> Result<()> {
    let mut body = String::new();
    body.push_str("<div class=\"wrap\">");
    body.push_str(&hero(
        &format!("{} · dead hosts", data.domain),
        "Hosts that were unreachable or timed out are removed from the active host pages.",
    ));

    body.push_str(&section_start("Discovery dead hosts"));
    body.push_str("<div class=\"card-list\">");
    for dead in &data.discovery_dead {
        body.push_str(&dead_card(dead));
    }
    body.push_str("</div>");
    body.push_str(&section_end());

    body.push_str(&section_start("Derived dead hosts"));
    body.push_str("<div class=\"card-list\">");
    for dead in &data.derived_dead {
        body.push_str(&dead_card(dead));
    }
    body.push_str("</div>");
    body.push_str(&section_end());

    body.push_str("<div class=\"footer-links\"><a href=\"index.html\">Back to index</a></div>");
    body.push_str("</div>");

    fs::write(path, page("Dead Hosts", &body, "assets/report.css"))?;
    Ok(())
}

fn write_host_page(path: &Path, host: &HostReport) -> Result<()> {
    let mut body = String::new();
    body.push_str("<div class=\"wrap\">");
    body.push_str(&hero(
        &host.host,
        host.profile_summary.as_deref().unwrap_or("Subdomain page"),
    ));

    body.push_str(&stats_grid(&[
        ("Tests", host.results.len().to_string()),
        ("Pass", host.counts.pass.to_string()),
        ("Warn", host.counts.warn.to_string()),
        ("Error", host.counts.error.to_string()),
    ]));

    if !host.profiles.is_empty() {
        body.push_str(&section_start("Site Profile"));
        body.push_str("<div class=\"chips\">");
        for profile in &host.profiles {
            body.push_str(&format!(
                "<span class=\"chip\">{} · {} · {}</span>",
                escape_html(&profile.kind),
                escape_html(profile.provider.as_deref().unwrap_or("unknown")),
                escape_html(&format!("{:.0}%", profile.confidence * 100.0))
            ));
        }
        body.push_str("</div>");
        body.push_str(&section_end());
    }

    body.push_str(&section_start("Tests"));
    body.push_str("<div class=\"card-list\">");
    for result in &host.results {
        body.push_str(&test_card(result));
    }
    body.push_str("</div>");
    body.push_str(&section_end());

    body.push_str("<div class=\"footer-links\"><a href=\"../index.html\">Back to index</a><a href=\"../dead.html\">Dead hosts</a></div>");
    body.push_str("</div>");

    fs::write(path, page(&host.host, &body, "../assets/report.css"))?;
    Ok(())
}

fn page(title: &str, body: &str, css_href: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{}</title><link rel=\"stylesheet\" href=\"{}\"></head><body>{}</body></html>",
        escape_html(title),
        escape_html(css_href),
        body
    )
}

fn hero(title: &str, subtitle: &str) -> String {
    format!(
        "<div class=\"hero\"><div><h1>{}</h1><p>{}</p></div><div class=\"chips\"><span class=\"badge\">HTML bundle</span><span class=\"badge\">JSON source</span></div></div>",
        escape_html(title),
        escape_html(subtitle)
    )
}

fn stats_grid(items: &[(&str, String)]) -> String {
    let mut out = String::from("<div class=\"grid cols-4\">");
    for (label, value) in items {
        out.push_str(&format!(
            "<div class=\"stat\"><span class=\"k\">{}</span><span class=\"v\">{}</span></div>",
            escape_html(label),
            escape_html(value)
        ));
    }
    out.push_str("</div>");
    out
}

fn section_start(title: &str) -> String {
    format!(
        "<div class=\"panel section\"><h2>{}</h2>",
        escape_html(title)
    )
}

fn section_end() -> String {
    "</div>".to_string()
}

fn profile_card(profile: &SiteProfile) -> String {
    format!(
        "<div class=\"card\"><h4>{}</h4><div class=\"chips\"><span class=\"chip\">{}</span>{}</div><p class=\"muted\">confidence: {}</p><pre>{}</pre></div>",
        escape_html(&profile.host),
        escape_html(&profile.kind),
        profile
            .provider
            .as_ref()
            .map(|provider| format!("<span class=\"chip\">{}</span>", escape_html(provider)))
            .unwrap_or_default(),
        escape_html(&format!("{:.0}%", profile.confidence * 100.0)),
        escape_html(&profile.signals.join("\n"))
    )
}

fn host_card(host: &HostReport) -> String {
    format!(
        "<div class=\"card\"><h4><a href=\"hosts/{}.html\">{}</a></h4><div class=\"chips\">{}</div><p class=\"muted\">{} test result(s)</p></div>",
        escape_html(&slugify(&host.host)),
        escape_html(&host.host),
        chip_for_status(&host.overall_status),
        host.results.len()
    )
}

fn dead_card(dead: &DeadEntry) -> String {
    format!(
        "<div class=\"card\"><h4>{}</h4><div class=\"chips\"><span class=\"chip error\">dead</span><span class=\"chip\">{}</span></div><pre>{}</pre></div>",
        escape_html(&dead.host),
        escape_html(&dead.source),
        escape_html(&dead.reason)
    )
}

fn test_card(result: &TestOutput) -> String {
    let notes = result.notes.clone().unwrap_or_default();
    let recommendations = if result.recommendations.is_empty() {
        String::new()
    } else {
        result.recommendations.join("\n")
    };
    let evidence = if result.evidence.is_null() {
        String::new()
    } else {
        serde_json::to_string_pretty(&result.evidence).unwrap_or_default()
    };

    let mut card = String::new();
    card.push_str(&format!(
        "<div class=\"card\"><h4>{}</h4><div class=\"chips\"><span class=\"chip {}\">{}</span><span class=\"chip\">severity: {}</span><span class=\"chip\">target: {}</span></div>",
        escape_html(&result.test_id.0),
        status_class(&result.status),
        escape_html(status_label(&result.status)),
        escape_html(severity_label(&result.severity)),
        escape_html(&display_target(&result.target))
    ));

    if !notes.trim().is_empty() {
        card.push_str(&format!("<p>{}</p>", escape_html(&notes)));
    }
    if !recommendations.trim().is_empty() {
        card.push_str(&format!(
            "<details><summary>Recommendations</summary><pre>{}</pre></details>",
            escape_html(&recommendations)
        ));
    }
    if !evidence.trim().is_empty() {
        card.push_str(&format!(
            "<details><summary>Evidence</summary><pre>{}</pre></details>",
            escape_html(&evidence)
        ));
    }
    card.push_str("</div>");
    card
}

fn chip_for_status(status: &TestStatus) -> String {
    format!(
        "<span class=\"chip {}\">{}</span>",
        status_class(status),
        escape_html(status_label(status))
    )
}

fn status_class(status: &TestStatus) -> &'static str {
    match status {
        TestStatus::Pass => "pass",
        TestStatus::Warn => "warn",
        TestStatus::Fail => "fail",
        TestStatus::Error => "error",
        TestStatus::Info => "info",
        TestStatus::Skipped => "skipped",
    }
}

fn status_label(status: &TestStatus) -> &'static str {
    match status {
        TestStatus::Pass => "pass",
        TestStatus::Warn => "warn",
        TestStatus::Fail => "fail",
        TestStatus::Error => "error",
        TestStatus::Info => "info",
        TestStatus::Skipped => "skipped",
    }
}

fn severity_label(severity: &TestSeverity) -> &'static str {
    match severity {
        TestSeverity::Low => "low",
        TestSeverity::Medium => "medium",
        TestSeverity::High => "high",
        TestSeverity::Critical => "critical",
        TestSeverity::Informational => "informational",
    }
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn slugify(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => out.push(ch),
            '.' => out.push('_'),
            _ => out.push('_'),
        }
    }
    if out.is_empty() {
        "host".to_string()
    } else {
        out
    }
}

#[derive(Debug, Clone)]
struct HostReport {
    host: String,
    results: Vec<TestOutput>,
    profiles: Vec<SiteProfile>,
    profile_summary: Option<String>,
    overall_status: TestStatus,
    counts: StatusCounts,
}

#[derive(Debug, Clone, Default)]
struct StatusCounts {
    pass: usize,
    warn: usize,
    fail: usize,
    error: usize,
    skipped: usize,
    info: usize,
}

#[derive(Debug, Clone)]
struct DeadEntry {
    host: String,
    reason: String,
    source: String,
}

#[derive(Debug)]
struct ReportData {
    domain: String,
    active_hosts: Vec<HostReport>,
    dead: Vec<DeadEntry>,
    discovery_dead: Vec<DeadEntry>,
    derived_dead: Vec<DeadEntry>,
    site_profiles: Vec<SiteProfile>,
    active_test_count: usize,
}

impl ReportData {
    fn load(results_dir: &Path) -> Result<Self> {
        let site_profiles = read_json::<Vec<SiteProfile>>(&results_dir.join("site_profiles.json"))
            .unwrap_or_default();
        let discovery_dead = read_json::<Vec<DeadHost>>(&results_dir.join("dead_hosts.json"))
            .unwrap_or_default()
            .into_iter()
            .filter(|dead| is_site_like_host(&dead.host))
            .map(|dead| DeadEntry {
                host: dead.host,
                reason: dead.reason,
                source: "discovery".to_string(),
            })
            .collect::<Vec<_>>();

        let mut results_by_host: BTreeMap<String, Vec<TestOutput>> = BTreeMap::new();
        for test_dir in fs::read_dir(results_dir)? {
            let test_dir = test_dir?;
            if !test_dir.file_type()?.is_dir() {
                continue;
            }
            for file in fs::read_dir(test_dir.path())? {
                let file = file?;
                if !file.file_type()?.is_file() {
                    continue;
                }
                if file.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                    continue;
                }
                let output: TestOutput = read_json(&file.path())?;
                let host = host_key(&output.target);
                if is_site_like_host(&host) {
                    results_by_host.entry(host).or_default().push(output);
                }
            }
        }

        let profile_map = profiles_by_host(&site_profiles);
        let discovery_dead_hosts: BTreeSet<String> = discovery_dead
            .iter()
            .map(|dead| dead.host.to_lowercase())
            .collect();

        let mut active_hosts = Vec::new();
        let mut derived_dead = Vec::new();
        let mut active_test_count = 0;

        for (host, mut results) in results_by_host {
            results.sort_by(|a, b| a.test_id.0.cmp(&b.test_id.0).then(a.target.cmp(&b.target)));
            let profiles = profile_map.get(&host).cloned().unwrap_or_default();
            let counts = count_results(&results);
            let overall_status = overall_status(&counts);
            let dead_reason = derive_dead_reason(&host, &results, &discovery_dead_hosts);

            if let Some(reason) = dead_reason {
                derived_dead.push(DeadEntry {
                    host: host.clone(),
                    reason,
                    source: "execution".to_string(),
                });
                continue;
            }

            active_test_count += results.len();
            let profile_summary = profiles.first().map(|profile| {
                let provider = profile.provider.as_deref().unwrap_or("unknown");
                format!("{} · {}", profile.kind, provider)
            });

            active_hosts.push(HostReport {
                host,
                results,
                profiles,
                profile_summary,
                overall_status,
                counts,
            });
        }

        let mut dead = discovery_dead.clone();
        dead.extend(derived_dead.clone());
        dead.sort_by(|a, b| a.host.cmp(&b.host));

        Ok(Self {
            domain: infer_domain(results_dir, &active_hosts, &site_profiles, &dead),
            active_hosts,
            dead,
            discovery_dead,
            derived_dead,
            site_profiles,
            active_test_count,
        })
    }
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(value)
}

fn profiles_by_host(profiles: &[SiteProfile]) -> BTreeMap<String, Vec<SiteProfile>> {
    let mut map: BTreeMap<String, Vec<SiteProfile>> = BTreeMap::new();
    for profile in profiles {
        map.entry(profile.host.to_lowercase())
            .or_default()
            .push(profile.clone());
    }
    map
}

fn count_results(results: &[TestOutput]) -> StatusCounts {
    let mut counts = StatusCounts::default();
    for result in results {
        match result.status {
            TestStatus::Pass => counts.pass += 1,
            TestStatus::Warn => counts.warn += 1,
            TestStatus::Fail => counts.fail += 1,
            TestStatus::Error => counts.error += 1,
            TestStatus::Info => counts.info += 1,
            TestStatus::Skipped => counts.skipped += 1,
        }
    }
    counts
}

fn overall_status(counts: &StatusCounts) -> TestStatus {
    if counts.error > 0 {
        TestStatus::Error
    } else if counts.fail > 0 {
        TestStatus::Fail
    } else if counts.warn > 0 {
        TestStatus::Warn
    } else if counts.pass > 0 {
        TestStatus::Pass
    } else if counts.info > 0 {
        TestStatus::Info
    } else {
        TestStatus::Skipped
    }
}

fn derive_dead_reason(
    host: &str,
    results: &[TestOutput],
    discovery_dead_hosts: &BTreeSet<String>,
) -> Option<String> {
    if discovery_dead_hosts.contains(&host.to_lowercase()) {
        return Some("discovery marked host unreachable".to_string());
    }

    if results.is_empty() {
        return None;
    }

    let non_skipped: Vec<&TestOutput> = results
        .iter()
        .filter(|result| result.status != TestStatus::Skipped)
        .collect();
    if non_skipped.is_empty() {
        return None;
    }

    if non_skipped.iter().all(|result| {
        result.status == TestStatus::Error
            && result
                .notes
                .as_deref()
                .map(is_unavailable_note)
                .unwrap_or(false)
    }) {
        let mut reasons = BTreeSet::new();
        for result in non_skipped {
            if let Some(notes) = &result.notes {
                reasons.insert(notes.clone());
            }
        }
        return Some(if reasons.is_empty() {
            "all tests timed out or were unreachable".to_string()
        } else {
            reasons.into_iter().collect::<Vec<_>>().join(" | ")
        });
    }

    None
}

fn is_unavailable_note(note: &str) -> bool {
    let lower = note.to_lowercase();
    lower.contains("timed out")
        || lower.contains("could not resolve host")
        || lower.contains("resolution lifetime expired")
        || lower.contains("dns operation timed out")
        || lower.contains("failed to connect")
        || lower.contains("connection refused")
        || lower.contains("host unreachable")
        || lower.contains("no route to host")
}

fn host_key(target: &str) -> String {
    let trimmed = target.trim();
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    without_scheme
        .split('|')
        .next()
        .unwrap_or(without_scheme)
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .trim_end_matches('.')
        .to_lowercase()
}

fn display_target(target: &str) -> String {
    if let Some((host, suffix)) = target.split_once('|') {
        format!("{} @ {}", host.trim(), suffix.trim())
    } else {
        target.to_string()
    }
}

fn infer_domain(
    results_dir: &Path,
    active_hosts: &[HostReport],
    site_profiles: &[SiteProfile],
    dead: &[DeadEntry],
) -> String {
    let mut candidates = Vec::new();
    candidates.extend(active_hosts.iter().map(|host| host.host.as_str()));
    candidates.extend(site_profiles.iter().map(|profile| profile.host.as_str()));
    candidates.extend(dead.iter().map(|dead| dead.host.as_str()));

    if let Some(host) = candidates
        .into_iter()
        .filter(|host| is_site_like_host(host))
        .min_by_key(|host| (host.split('.').count(), host.len()))
    {
        return host.to_string();
    }

    results_dir
        .parent()
        .and_then(|path| path.file_name())
        .and_then(|name| name.to_str())
        .map(|name| name.to_string())
        .unwrap_or_else(|| "report".to_string())
}

fn is_site_like_host(host: &str) -> bool {
    let host = host.trim().to_lowercase();
    if host.is_empty() {
        return false;
    }
    host.split('.')
        .all(|label| !label.is_empty() && !label.starts_with('_'))
}
