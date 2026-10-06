//! Bounded, source-independent JSON node extraction for future owned SQL relations.
//!
//! The caller supplies *stored* bytes and chooses an interpretation. Declared
//! JSON is an invariant and malformed input fails closed. A TEXT cell that merely
//! parses as JSON is a candidate: its nodes describe the stored text's syntax,
//! never the type originally authored by a user. In particular, the facet
//! event format has already erased whether `{"a":1}` was an object or a string.
//!
//! This parser keeps numeric lexemes and duplicate object members. Parsing
//! through `serde_json::Value` would normalize numbers and overwrite earlier
//! duplicate keys, making an "exhaustive" node projection untrue.

use thiserror::Error;

pub const MAX_JSON_SOURCE_BYTES: usize = 256 * 1024;
pub const MAX_JSON_DEPTH: usize = 64;
pub const MAX_JSON_NODES: usize = 4096;
pub const MAX_JSON_PROJECTED_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Interpretation {
    /// The source column's storage contract declares this cell to be JSON.
    DeclaredJson,
    /// Parsing stored TEXT says nothing about its originally authored type.
    ParsedTextCandidate,
}

impl Interpretation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeclaredJson => "declared_json",
            Self::ParsedTextCandidate => "parsed_text_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeType {
    Object,
    Array,
    String,
    Number,
    Boolean,
    Null,
}

impl NodeType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Object => "object",
            Self::Array => "array",
            Self::String => "string",
            Self::Number => "number",
            Self::Boolean => "boolean",
            Self::Null => "null",
        }
    }
}

/// A preorder occurrence, including the root and empty containers. `path` is
/// an RFC 6901 JSON Pointer, with `""` for the root. Paths are not unique when
/// an object repeats a key; `ordinal` distinguishes those occurrences.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonNode {
    pub ordinal: usize,
    pub path: String,
    pub parent_path: Option<String>,
    /// The parent occurrence in this document. Paths alone are ambiguous when
    /// an object repeats a key, so consumers must use this to join to parents.
    pub parent_ordinal: Option<usize>,
    pub member_key: Option<String>,
    pub array_index: Option<usize>,
    pub depth: usize,
    pub node_type: NodeType,
    pub text_value: Option<String>,
    /// The exact JSON number token, without floating-point conversion.
    pub number_text: Option<String>,
    pub bool_value: Option<bool>,
}

/// The interpretation travels with its nodes so a caller cannot silently
/// present a syntactic TEXT candidate as an authenticated JSON value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonDocument {
    pub interpretation: Interpretation,
    pub nodes: Vec<JsonNode>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ExtractError {
    #[error("JSON source exceeds {MAX_JSON_SOURCE_BYTES} bytes")]
    SourceTooLarge,
    #[error("JSON nesting exceeds depth {MAX_JSON_DEPTH}")]
    TooDeep,
    #[error("JSON source exceeds {MAX_JSON_NODES} nodes")]
    TooManyNodes,
    #[error("JSON node projection exceeds {MAX_JSON_PROJECTED_BYTES} bytes")]
    ProjectionTooLarge,
    #[error("invalid JSON at byte {offset}")]
    InvalidJson { offset: usize },
}

/// Extract all nodes from one stored cell. A malformed TEXT candidate returns
/// `Ok(None)`; a malformed declared JSON cell returns `Err(InvalidJson)`.
/// Resource-limit errors always fail closed, for either interpretation.
pub fn extract_json_nodes(
    source: &str,
    interpretation: Interpretation,
) -> Result<Option<JsonDocument>, ExtractError> {
    if source.len() > MAX_JSON_SOURCE_BYTES {
        return Err(ExtractError::SourceTooLarge);
    }
    let mut parser = Parser {
        source,
        offset: 0,
        nodes: Vec::new(),
        projected_bytes: 0,
    };
    let result = parser
        .parse_value(String::new(), None, None, None, None, 0)
        .and_then(|()| {
            parser.skip_space();
            if parser.offset == source.len() {
                Ok(())
            } else {
                Err(parser.invalid())
            }
        });
    match result {
        Ok(()) => Ok(Some(JsonDocument {
            interpretation,
            nodes: parser.nodes,
        })),
        Err(ExtractError::InvalidJson { .. })
            if interpretation == Interpretation::ParsedTextCandidate =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

struct Parser<'a> {
    source: &'a str,
    offset: usize,
    nodes: Vec<JsonNode>,
    projected_bytes: usize,
}

impl Parser<'_> {
    fn invalid(&self) -> ExtractError {
        ExtractError::InvalidJson {
            offset: self.offset,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.source.as_bytes().get(self.offset).copied()
    }

    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.offset += 1;
        }
    }

    fn take(&mut self, byte: u8) -> Result<(), ExtractError> {
        if self.peek() != Some(byte) {
            return Err(self.invalid());
        }
        self.offset += 1;
        Ok(())
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), ExtractError> {
        if !self.source.as_bytes()[self.offset..].starts_with(literal) {
            return Err(self.invalid());
        }
        self.offset += literal.len();
        Ok(())
    }

    fn string(&mut self) -> Result<String, ExtractError> {
        self.take(b'"')?;
        let start = self.offset - 1;
        while let Some(byte) = self.peek() {
            self.offset += 1;
            match byte {
                b'"' => {
                    return serde_json::from_str(&self.source[start..self.offset])
                        .map_err(|_| self.invalid());
                }
                b'\\' => {
                    if self.peek().is_none() {
                        return Err(self.invalid());
                    }
                    self.offset += 1;
                }
                _ => {}
            }
        }
        Err(self.invalid())
    }

    fn number(&mut self) -> Result<String, ExtractError> {
        let start = self.offset;
        if self.peek() == Some(b'-') {
            self.offset += 1;
        }
        match self.peek() {
            Some(b'0') => self.offset += 1,
            Some(b'1'..=b'9') => {
                self.offset += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.offset += 1;
                }
            }
            _ => return Err(self.invalid()),
        }
        if self.peek() == Some(b'.') {
            self.offset += 1;
            self.digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.offset += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.offset += 1;
            }
            self.digits()?;
        }
        Ok(self.source[start..self.offset].to_string())
    }

    fn digits(&mut self) -> Result<(), ExtractError> {
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(self.invalid());
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.offset += 1;
        }
        Ok(())
    }

    fn budget(&mut self, bytes: usize) -> Result<(), ExtractError> {
        self.projected_bytes = self.projected_bytes.saturating_add(bytes);
        if self.projected_bytes > MAX_JSON_PROJECTED_BYTES {
            return Err(ExtractError::ProjectionTooLarge);
        }
        Ok(())
    }

    fn parse_value(
        &mut self,
        path: String,
        parent_path: Option<String>,
        parent_ordinal: Option<usize>,
        member_key: Option<String>,
        array_index: Option<usize>,
        depth: usize,
    ) -> Result<(), ExtractError> {
        if depth > MAX_JSON_DEPTH {
            return Err(ExtractError::TooDeep);
        }
        if self.nodes.len() >= MAX_JSON_NODES {
            return Err(ExtractError::TooManyNodes);
        }
        self.skip_space();
        let ordinal = self.nodes.len();
        let node_type = match self.peek() {
            Some(b'{') => NodeType::Object,
            Some(b'[') => NodeType::Array,
            Some(b'"') => NodeType::String,
            Some(b'-' | b'0'..=b'9') => NodeType::Number,
            Some(b't' | b'f') => NodeType::Boolean,
            Some(b'n') => NodeType::Null,
            _ => return Err(self.invalid()),
        };
        self.budget(
            path.len()
                + parent_path.as_ref().map_or(0, String::len)
                + member_key.as_ref().map_or(0, String::len)
                + 64,
        )?;
        self.nodes.push(JsonNode {
            ordinal,
            path: path.clone(),
            parent_path,
            parent_ordinal,
            member_key,
            array_index,
            depth,
            node_type,
            text_value: None,
            number_text: None,
            bool_value: None,
        });
        match node_type {
            NodeType::Object => {
                self.take(b'{')?;
                self.skip_space();
                if self.peek() == Some(b'}') {
                    self.offset += 1;
                    return Ok(());
                }
                loop {
                    self.skip_space();
                    let key = self.string()?;
                    self.skip_space();
                    self.take(b':')?;
                    let child_path = format!("{path}/{}", escape_pointer_token(&key));
                    self.parse_value(
                        child_path,
                        Some(path.clone()),
                        Some(ordinal),
                        Some(key),
                        None,
                        depth + 1,
                    )?;
                    self.skip_space();
                    match self.peek() {
                        Some(b',') => self.offset += 1,
                        Some(b'}') => {
                            self.offset += 1;
                            return Ok(());
                        }
                        _ => return Err(self.invalid()),
                    }
                }
            }
            NodeType::Array => {
                self.take(b'[')?;
                self.skip_space();
                if self.peek() == Some(b']') {
                    self.offset += 1;
                    return Ok(());
                }
                let mut index = 0;
                loop {
                    self.parse_value(
                        format!("{path}/{index}"),
                        Some(path.clone()),
                        Some(ordinal),
                        None,
                        Some(index),
                        depth + 1,
                    )?;
                    index += 1;
                    self.skip_space();
                    match self.peek() {
                        Some(b',') => self.offset += 1,
                        Some(b']') => {
                            self.offset += 1;
                            return Ok(());
                        }
                        _ => return Err(self.invalid()),
                    }
                }
            }
            NodeType::String => {
                let text = self.string()?;
                self.budget(text.len())?;
                self.nodes[ordinal].text_value = Some(text);
            }
            NodeType::Number => {
                let number = self.number()?;
                self.budget(number.len())?;
                self.nodes[ordinal].number_text = Some(number);
            }
            NodeType::Boolean => {
                let value = self.peek() == Some(b't');
                self.literal(if value { b"true" } else { b"false" })?;
                self.nodes[ordinal].bool_value = Some(value);
            }
            NodeType::Null => self.literal(b"null")?,
        }
        Ok(())
    }
}

fn escape_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declared(source: &str) -> Vec<JsonNode> {
        extract_json_nodes(source, Interpretation::DeclaredJson)
            .unwrap()
            .unwrap()
            .nodes
    }

    #[test]
    fn duplicate_keys_and_pointer_escapes_keep_all_occurrences() {
        let nodes = declared(r#"{"a/b~c":1,"a/b~c":{"":null}}"#);
        assert_eq!(
            nodes.iter().map(|n| n.path.as_str()).collect::<Vec<_>>(),
            ["", "/a~1b~0c", "/a~1b~0c", "/a~1b~0c/"]
        );
        assert_eq!(
            nodes.iter().map(|n| n.ordinal).collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        assert_eq!(nodes[1].member_key.as_deref(), Some("a/b~c"));
        assert_eq!(nodes[3].parent_path.as_deref(), Some("/a~1b~0c"));
        assert_eq!(nodes[3].node_type, NodeType::Null);
    }

    #[test]
    fn parent_ordinals_disambiguate_nested_duplicate_keys() {
        let nodes = declared(r#"{"a":{"x":1},"a":{"x":2},"arr":[{"x":3},{"x":4}]}"#);
        assert_eq!(nodes.len(), 10);
        assert_eq!(nodes[0].parent_ordinal, None);
        assert_eq!(nodes[1].parent_ordinal, Some(0));
        assert_eq!(nodes[3].parent_ordinal, Some(0));
        assert_eq!(nodes[2].path, nodes[4].path);
        assert_eq!(nodes[2].parent_path, nodes[4].parent_path);
        assert_eq!(nodes[2].parent_ordinal, Some(1));
        assert_eq!(nodes[4].parent_ordinal, Some(3));
        assert_eq!(nodes[6].parent_ordinal, Some(5));
        assert_eq!(nodes[8].parent_ordinal, Some(5));
        assert_eq!(nodes[7].parent_ordinal, Some(6));
        assert_eq!(nodes[9].parent_ordinal, Some(8));
    }

    #[test]
    fn exact_number_lexemes_and_array_positions() {
        let nodes = declared(r#"[-0,1.00,2E+09,123456789012345678901234567890]"#);
        assert_eq!(
            nodes
                .iter()
                .skip(1)
                .map(|n| n.number_text.as_deref().unwrap())
                .collect::<Vec<_>>(),
            ["-0", "1.00", "2E+09", "123456789012345678901234567890"]
        );
        assert_eq!(nodes[4].array_index, Some(3));
        assert_eq!(nodes[4].path, "/3");
    }

    #[test]
    fn roots_null_and_empty_containers_are_nodes() {
        let nodes = declared(r#"{"a":[],"b":{},"c":null,"d":true,"e":"x"}"#);
        assert_eq!(nodes.len(), 6);
        assert_eq!(nodes[0].node_type, NodeType::Object);
        assert_eq!(nodes[1].node_type, NodeType::Array);
        assert_eq!(nodes[2].node_type, NodeType::Object);
        assert_eq!(nodes[3].node_type, NodeType::Null);
        assert_eq!(nodes[4].bool_value, Some(true));
        assert_eq!(nodes[5].text_value.as_deref(), Some("x"));
        assert_eq!(declared("null")[0].path, "");
    }

    #[test]
    fn candidate_parse_does_not_recover_authored_type() {
        let stored = r#"{"a":1}"#;
        let candidate = extract_json_nodes(stored, Interpretation::ParsedTextCandidate)
            .unwrap()
            .unwrap();
        assert_eq!(candidate.nodes, declared(stored));
        assert_eq!(
            candidate.interpretation,
            Interpretation::ParsedTextCandidate
        );
        assert_eq!(
            Interpretation::ParsedTextCandidate.as_str(),
            "parsed_text_candidate"
        );
        assert_eq!(
            extract_json_nodes("plain text", Interpretation::ParsedTextCandidate).unwrap(),
            None
        );
        assert!(matches!(
            extract_json_nodes("plain text", Interpretation::DeclaredJson),
            Err(ExtractError::InvalidJson { .. })
        ));
    }

    #[test]
    fn malformed_strings_numbers_and_trailing_tokens_fail_closed() {
        for source in [r#"{"x":"\uD800"}"#, "01", "1.", "1e+", "[1,]", "true false"] {
            assert!(
                matches!(
                    extract_json_nodes(source, Interpretation::DeclaredJson),
                    Err(ExtractError::InvalidJson { .. })
                ),
                "{source}"
            );
            assert_eq!(
                extract_json_nodes(source, Interpretation::ParsedTextCandidate).unwrap(),
                None
            );
        }
    }

    #[test]
    fn resource_limits_are_errors_even_for_candidates() {
        for interpretation in [
            Interpretation::DeclaredJson,
            Interpretation::ParsedTextCandidate,
        ] {
            let huge = format!("\"{}\"", "a".repeat(MAX_JSON_SOURCE_BYTES));
            assert_eq!(
                extract_json_nodes(&huge, interpretation),
                Err(ExtractError::SourceTooLarge)
            );
            let deep = format!(
                "{}0{}",
                "[".repeat(MAX_JSON_DEPTH + 1),
                "]".repeat(MAX_JSON_DEPTH + 1)
            );
            assert_eq!(
                extract_json_nodes(&deep, interpretation),
                Err(ExtractError::TooDeep)
            );
            let many = format!("[{}]", vec!["0"; MAX_JSON_NODES].join(","));
            assert_eq!(
                extract_json_nodes(&many, interpretation),
                Err(ExtractError::TooManyNodes)
            );
        }
    }
}
