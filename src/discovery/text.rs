//! Passive text extraction and classification helpers.

use std::collections::BTreeSet;

use super::canonical_host;

/// Common frontend/framework fingerprints that still count as basic sites.
pub(super) const REACT_MARKERS: &[&str] = &[
    "data-reactroot",
    "react-refresh",
    "__react",
    "react/jsx-runtime",
    "__webpack_hmr",
];

pub(super) const VITE_MARKERS: &[&str] = &[
    "@vite/client",
    "import.meta.hot",
    "data-vite-dev-id",
    "vite-preload-helper",
];

pub(super) const ANGULAR_MARKERS: &[&str] =
    &["ng-version", "ng-app", "angular.js", "ng-server-context"];

pub(super) const NEXTJS_MARKERS: &[&str] = &["__next_data__", "/_next/", "next.js"];

pub(super) const VUE_MARKERS: &[&str] = &["__vue__", "vue-app", "data-v-"];

pub(super) const SVELTEKIT_MARKERS: &[&str] = &["__sveltekit", "sveltekit"];

pub(super) const WORDPRESS_MARKERS: &[&str] = &[
    "wp-content/",
    "wp-includes/",
    "wp-json",
    "xmlrpc.php",
    "wp-login.php",
    "meta name=\"generator\" content=\"wordpress",
];

pub(super) const GHOST_MARKERS: &[&str] = &[
    "data-ghost",
    "/ghost/api/",
    "meta name=\"generator\" content=\"ghost",
    "ghost-content/",
    "ghost.org",
];

pub(super) const WIX_MARKERS: &[&str] = &[
    "static.wixstatic.com",
    "wixstatic.com",
    "wixsite.com",
    "wix-image://",
    "meta property=\"og:site_name\" content=\"wix",
];

pub(super) const WEEBLY_MARKERS: &[&str] = &[
    "cdn2.editmysite.com",
    "editmysite.com",
    "weebly.com",
    "weeblysite.com",
];

pub(super) const SQUARESPACE_MARKERS: &[&str] = &[
    "static1.squarespace.com",
    "images.squarespace-cdn.com",
    "sqspcdn.com",
    "data-squarespace-siteid",
    "meta name=\"generator\" content=\"squarespace",
    "squarespace.com",
];

pub(super) const SQUARE_MARKERS: &[&str] = &[
    "square.site",
    "squareup.com",
    "cdn.square.site",
    "images.squareup-cdn.com",
];

pub(super) const SHOPIFY_MARKERS: &[&str] = &[
    "cdn.shopify.com",
    "myshopify.com",
    "shopifycdn.net",
    "x-shopify",
    "shopify theme",
];

/// Pull public hostnames from a single page/asset using a conservative parser.
pub(super) fn extract_hosts(text: &str) -> BTreeSet<String> {
    let mut hosts = BTreeSet::new();
    for token in extract_urls(text) {
        if let Some(host) = url_to_host(&token) {
            hosts.insert(host);
        }
    }
    hosts
}

/// Extract both URL hosts and bare in-scope hostname tokens from surface text.
pub(super) fn extract_surface_hosts(text: &str, apex: &str) -> BTreeSet<String> {
    let mut hosts = extract_hosts(text);
    hosts.extend(extract_bare_hosts(text, apex));
    hosts
}

fn extract_bare_hosts(text: &str, apex: &str) -> BTreeSet<String> {
    let mut hosts = BTreeSet::new();
    let apex = canonical_host(apex);
    let apex_suffix = format!(".{apex}");

    for raw in text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';'
            )
    }) {
        let mut token = raw.trim();
        if token.is_empty() {
            continue;
        }

        token = token
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_start_matches("//")
            .trim_start_matches("mailto:")
            .trim_start_matches("*.");

        token = token.split(['/', '?', '#']).next().unwrap_or(token);
        token = token
            .trim_matches(|c: char| {
                matches!(
                    c,
                    '"' | '\'' | ',' | ')' | '(' | '<' | '>' | '[' | ']' | '{' | '}' | ';'
                )
            })
            .trim_end_matches('.');

        if token.is_empty() {
            continue;
        }

        if let Some((host, port)) = token.rsplit_once(':') {
            if !port.is_empty() && port.chars().all(|ch| ch.is_ascii_digit()) {
                token = host;
            }
        }

        if !looks_like_bare_hostname(token, &apex, &apex_suffix) {
            continue;
        }

        hosts.insert(canonical_host(token));
    }

    hosts
}

fn looks_like_bare_hostname(token: &str, apex: &str, apex_suffix: &str) -> bool {
    if token.is_empty() || token.contains('/') || token.contains('@') {
        return false;
    }

    let token = token.trim_end_matches('.');
    if token.is_empty() || !token.contains('.') {
        return false;
    }

    if !token
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
    {
        return false;
    }

    let token = canonical_host(token);
    token == apex || token.ends_with(apex_suffix)
}

/// Extract lightweight signal strings that help explain the classification.
pub(super) fn extract_signals(text: &str) -> Vec<String> {
    let mut signals = Vec::new();
    signals.extend(markers_to_signals(text, "wordpress", WORDPRESS_MARKERS));
    signals.extend(markers_to_signals(text, "ghost", GHOST_MARKERS));
    signals.extend(markers_to_signals(text, "wix", WIX_MARKERS));
    signals.extend(markers_to_signals(text, "weebly", WEEBLY_MARKERS));
    signals.extend(markers_to_signals(text, "square", SQUARE_MARKERS));
    signals.extend(markers_to_signals(text, "squarespace", SQUARESPACE_MARKERS));
    signals.extend(markers_to_signals(text, "shopify", SHOPIFY_MARKERS));
    signals.extend(markers_to_signals(text, "react", REACT_MARKERS));
    signals.extend(markers_to_signals(text, "vite", VITE_MARKERS));
    signals.extend(markers_to_signals(text, "angular", ANGULAR_MARKERS));
    signals.extend(markers_to_signals(text, "nextjs", NEXTJS_MARKERS));
    signals.extend(markers_to_signals(text, "vue", VUE_MARKERS));
    signals.extend(markers_to_signals(text, "sveltekit", SVELTEKIT_MARKERS));

    let lower = text.to_lowercase();
    if lower.contains("application/json") || lower.trim_start().starts_with('{') {
        signals.push("json".to_string());
    }
    signals
}

pub(super) fn markers_to_signals(text: &str, label: &str, markers: &[&str]) -> Vec<String> {
    let lower = text.to_lowercase();
    markers
        .iter()
        .filter(|marker| lower.contains(*marker))
        .map(|marker| format!("{label}:{marker}"))
        .collect()
}

pub(super) fn dedupe_signals(signals: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    signals
        .into_iter()
        .filter(|signal| seen.insert(signal.clone()))
        .collect()
}

pub(super) fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn url_to_host(token: &str) -> Option<String> {
    let token = token.trim();
    let token = token
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = token.split(['/', '?', '#']).next()?.trim_end_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(canonical_host(host))
    }
}

fn extract_urls(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for needle in ["https://", "http://"] {
        let mut remaining = text;
        while let Some(start) = remaining.find(needle) {
            let after = &remaining[start..];
            let end = after
                .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>'))
                .unwrap_or(after.len());
            let token =
                after[..end].trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ')' | '('));
            if !token.is_empty() {
                urls.push(token.to_string());
            }
            remaining = &after[end..];
        }
    }
    urls
}
