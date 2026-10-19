use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Unmatched {
    Passthrough,
    Deny,
}

impl Unmatched {
    pub fn as_str(&self) -> &'static str {
        match self {
            Unmatched::Passthrough => "passthrough",
            Unmatched::Deny => "deny",
        }
    }
}

impl FromStr for Unmatched {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "passthrough" => Ok(Self::Passthrough),
            "deny" => Ok(Self::Deny),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Role {
    pub name: String,
    pub unmatched: Unmatched,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InjectionKind {
    Header,
    Query,
}

impl InjectionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Query => "query",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Rule {
    pub id: i64,
    pub role: String,
    pub host_pattern: String,
    pub path_pattern: String,
    pub methods: Vec<String>,
    pub kind: InjectionKind,
    pub target_name: String,
    pub template: String,
    pub secret_id: i64,
}

/// A rule without its secret: the secret is attached with `with_secret` once it exists.
#[derive(Debug, Clone)]
pub struct RuleSpec {
    pub role: String,
    pub host_pattern: String,
    pub path_pattern: String,
    pub methods: Vec<String>,
    pub kind: InjectionKind,
    pub target_name: String,
    pub template: String,
}

impl RuleSpec {
    pub fn with_secret(self, secret_id: i64) -> NewRule {
        NewRule {
            role: self.role,
            host_pattern: self.host_pattern,
            path_pattern: self.path_pattern,
            methods: self.methods,
            kind: self.kind,
            target_name: self.target_name,
            template: self.template,
            secret_id,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct NewRule {
    pub role: String,
    pub host_pattern: String,
    #[serde(default = "star")]
    pub path_pattern: String,
    #[serde(default)]
    pub methods: Vec<String>,
    pub kind: InjectionKind,
    pub target_name: String,
    pub template: String,
    pub secret_id: i64,
}

fn star() -> String {
    "*".into()
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid rule: {0}")]
    Invalid(&'static str),
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    AlreadyExists,
    /// An identical rule (same role, host, path, methods, injection and secret) exists; carries its id.
    #[error("an identical rule already exists (rule {0})")]
    DuplicateRule(i64),
    #[error(transparent)]
    Core(#[from] sg_core::CoreError),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
}
