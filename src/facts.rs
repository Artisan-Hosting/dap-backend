//! Fact primitives produced by discovery modules.
//!
//! Facts are intentionally unopinionated records describing what we observed.
//! They power the planner, determine which tests run, and are eventually
//! serialized to support auditing and historical comparisons.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Opaque key/value map used to stash attributes without forcing a schema.
pub type FactAttributes = BTreeMap<String, serde_json::Value>;

/// Unique identifier for a fact within a run (e.g., `dns:TXT:_dmarc.example`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactId(pub String);

/// Fact entity descriptor, aligning with planner rules (e.g., `dns_record`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactEntity(pub String);

/// Complete fact structure used across the orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fact {
    /// Top-level target (usually the apex domain) the fact belongs to.
    pub target: String,
    /// Entity classification (dns_record, web_service, stack, ...).
    pub entity: FactEntity,
    /// Stable identifier per fact.
    pub id: FactId,
    /// Flexible attributes captured by discovery.
    pub attrs: FactAttributes,
}

impl Fact {
    /// Convenience helper for constructing a fact with string attributes.
    pub fn with_attrs<I, K, V>(
        target: impl Into<String>,
        entity: impl Into<String>,
        id: impl Into<String>,
        attrs: I,
    ) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<serde_json::Value>,
    {
        let mut map = FactAttributes::new();
        for (key, value) in attrs {
            map.insert(key.into(), value.into());
        }
        Self {
            target: target.into(),
            entity: FactEntity(entity.into()),
            id: FactId(id.into()),
            attrs: map,
        }
    }
}
