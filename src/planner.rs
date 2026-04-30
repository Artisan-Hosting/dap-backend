//! Lightweight rules engine for mapping facts to tests.
//!
//! This is a deliberately simple implementation to get engineers moving. The
//! configuration format is intentionally declarative so non-Rust contributors
//! can edit trigger logic via YAML without touching code.

use std::{collections::BTreeMap, fs, path::Path};

use serde::Deserialize;
use thiserror::Error;

use crate::{
    facts::Fact,
    tests::{PlannedTest, TestId},
};

/// Top-level configuration container parsed from YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

/// Individual rule entry describing a trigger and the tests to schedule.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub name: String,
    pub when: RuleCondition,
    pub run: Vec<String>,
}

/// Basic condition that matches on entity plus optional attribute equality.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleCondition {
    pub entity: String,
    #[serde(default)]
    pub attr_equals: BTreeMap<String, String>,
}

/// Errors returned while loading or interpreting rule files.
#[derive(Debug, Error)]
pub enum PlannerError {
    #[error("failed to read rules file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse rules yaml: {0}")]
    Parse(#[from] serde_yaml::Error),
}

/// Evaluates rules against discovered facts.
#[derive(Debug, Clone)]
pub struct RulesEngine {
    rules: Vec<Rule>,
}

impl RulesEngine {
    /// Load rules from a YAML file on disk.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, PlannerError> {
        let raw = fs::read_to_string(path)?;
        let rule_set: RuleSet = serde_yaml::from_str(&raw)?;
        Ok(Self {
            rules: rule_set.rules,
        })
    }

    /// Plan tests by applying each rule to all facts.
    pub fn plan(&self, facts: &[Fact]) -> Vec<PlannedTest> {
        let mut scheduled: BTreeMap<(TestId, String), BTreeMap<String, Fact>> = BTreeMap::new();

        for fact in facts {
            for rule in &self.rules {
                if !rule.when.matches(fact) {
                    continue;
                }

                for test_id in &rule.run {
                    let key = (TestId(test_id.clone()), fact.target.clone());
                    scheduled
                        .entry(key)
                        .or_default()
                        .entry(fact.id.0.clone())
                        .or_insert_with(|| fact.clone());
                }
            }
        }

        scheduled
            .into_iter()
            .map(|((test_id, _target), facts)| {
                PlannedTest::new(test_id.0, facts.into_values().collect())
            })
            .collect()
    }
}

impl RuleCondition {
    fn matches(&self, fact: &Fact) -> bool {
        if fact.entity.0 != self.entity {
            return false;
        }

        for (attr, expected) in &self.attr_equals {
            let actual = fact.attrs.get(attr);
            let matches = actual.map(|value| match value {
                serde_json::Value::String(s) => s == expected,
                serde_json::Value::Bool(b) => expected
                    .parse::<bool>()
                    .map(|parsed| parsed == *b)
                    .unwrap_or(false),
                serde_json::Value::Number(num) => num
                    .as_f64()
                    .map(|actual| {
                        expected
                            .parse::<f64>()
                            .map(|e| (actual - e).abs() < f64::EPSILON)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false),
                _ => false,
            });

            if matches != Some(true) {
                return false;
            }
        }

        true
    }
}
