//! CEL-free, versioned development guest wire contract. No executable host fallback.
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

pub const ABI: &str = "native.cel-scalar-guest/2";
pub const ABI_VERSION: u32 = 2;
pub const LANGUAGE: &str = "cel-subset@1";
pub const PROFILE: &str = "native.cel-scalar-dev/1";
pub const MAX_REQUEST: usize = 32 * 1024;
pub const MAX_RESPONSE: usize = 8192;
pub const MAX_SOURCE: usize = 16 * 1024;
pub const SAFE: i64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Declaration {
    pub language: String,
    pub profile: String,
    pub expression: String,
    pub bindings: Vec<Binding>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: Kind,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Int,
    Double,
    Bool,
    String,
}
impl Declaration {
    /// Byte/shape checks only; never a CEL acceptance decision.
    pub fn shape(&self) -> Result<(), &'static str> {
        if self.language != LANGUAGE || self.profile != PROFILE {
            return Err("unsupported language/profile");
        }
        if self.expression.is_empty() || self.expression.len() > 1024 || self.bindings.len() > 16 {
            return Err("declaration byte/count cap");
        }
        let mut names = BTreeSet::new();
        for b in &self.bindings {
            if b.name.is_empty()
                || b.name.len() > 64
                || !b.name.bytes().enumerate().all(|(i, c)| {
                    c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit())
                })
                || !names.insert(&b.name)
            {
                return Err("invalid/duplicate binding name");
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Check,
    Evaluate,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Check {
        declaration: Declaration,
    },
    Evaluate {
        declaration: Declaration,
        source: String,
    },
}
impl Request {
    pub fn declaration(&self) -> &Declaration {
        match self {
            Self::Check { declaration } | Self::Evaluate { declaration, .. } => declaration,
        }
    }
    pub fn mode(&self) -> Mode {
        match self {
            Self::Check { .. } => Mode::Check,
            Self::Evaluate { .. } => Mode::Evaluate,
        }
    }
}
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<T, D::Error> {
    T::deserialize(d)
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub abi: String,
    pub mode: Mode,
    pub check_policy: String,
    pub check_interim: bool,
    pub check_ok: bool,
    #[serde(deserialize_with = "present")]
    pub eval_policy: Option<String>,
    #[serde(deserialize_with = "present")]
    pub eval_interim: Option<bool>,
    #[serde(deserialize_with = "present")]
    pub value: Value,
    #[serde(deserialize_with = "present")]
    pub error_stage: Option<String>,
    #[serde(deserialize_with = "present")]
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn check_declarations_only_and_report_nullable_fields_are_required() {
        let request = r#"{"mode":"check","declaration":{"language":"cel-subset@1","profile":"native.cel-scalar-dev/1","expression":"1/0","bindings":[]}}"#;
        assert!(matches!(
            serde_json::from_str::<Request>(request).unwrap(),
            Request::Check { .. }
        ));
        assert!(serde_json::from_str::<Request>(&request.replacen(
            "\"mode\":\"check\"",
            "\"mode\":\"check\",\"source\":\"{}\"",
            1
        ))
        .is_err());
        let report = Report {
            abi: ABI.into(),
            mode: Mode::Check,
            check_policy: "cel-subset@1/p1".into(),
            check_interim: true,
            check_ok: true,
            eval_policy: None,
            eval_interim: None,
            value: Value::Null,
            error_stage: None,
            error: None,
        };
        let value = serde_json::to_value(report).unwrap();
        for key in [
            "eval_policy",
            "eval_interim",
            "value",
            "error_stage",
            "error",
        ] {
            let mut absent = value.clone();
            absent.as_object_mut().unwrap().remove(key);
            assert!(serde_json::from_value::<Report>(absent).is_err(), "{key}");
        }
        let text = serde_json::to_string(&value).unwrap();
        let duplicate = text.replacen('{', "{\"abi\":\"duplicate\",", 1);
        assert!(serde_json::from_str::<Report>(&duplicate).is_err());
    }
}
