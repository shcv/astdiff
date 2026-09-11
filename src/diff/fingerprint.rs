use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Write as _;
use tree_sitter::Node;

#[derive(Debug, Clone, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StringFingerprint {
    pub value: String,
    pub context: StringContext,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StringContext {
    ErrorMessage, // Contains "error", "fail", "exception"
    ConfigKey,    // Common config patterns
    ApiEndpoint,  // URLs, paths with /
    FilePath,     // Contains ~, /, \, .ext
    CommandName,  // Kebab-case strings
    Regular,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConstantValue {
    Number(i64),   // Integers only for now
    Float(String), // Store as string to avoid precision issues
    Regex(String), // Regex patterns
    Duration(u64), // setTimeout/setInterval values
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConstantFingerprint {
    pub value: ConstantValue,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ApiCallFingerprint {
    pub object: Option<String>,    // "process.env", "fs", etc
    pub method: String,            // "existsSync", "readFileSync"
    pub first_arg: Option<String>, // If it's a literal
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FunctionFingerprint {
    pub strings: Vec<StringFingerprint>,
    pub constants: Vec<ConstantFingerprint>,
    pub api_calls: Vec<ApiCallFingerprint>,
    pub size: usize,
}

pub struct FingerprintExtractor<'a> {
    source: &'a str,
}

impl<'a> FingerprintExtractor<'a> {
    pub fn new(source: &'a str) -> Self {
        Self { source }
    }

    pub fn extract_function_fingerprint(&self, node: Node) -> FunctionFingerprint {
        let mut strings = Vec::new();
        let mut constants = Vec::new();
        let mut api_calls = Vec::new();
        let mut node_count = 0;

        self.extract_fingerprints_recursive(
            node,
            &mut strings,
            &mut constants,
            &mut api_calls,
            &mut node_count,
        );

        FunctionFingerprint {
            strings,
            constants,
            api_calls,
            size: node_count,
        }
    }

    fn extract_fingerprints_recursive(
        &self,
        node: Node,
        strings: &mut Vec<StringFingerprint>,
        constants: &mut Vec<ConstantFingerprint>,
        api_calls: &mut Vec<ApiCallFingerprint>,
        node_count: &mut usize,
    ) {
        *node_count += 1;

        match node.kind() {
            "string" => {
                if let Some(value) = self.extract_string_value(node) {
                    if value.len() > 2 && !value.chars().all(|c| c.is_whitespace()) {
                        let context = self.classify_string(&value);
                        strings.push(StringFingerprint { value, context });
                    }
                }
            }
            "string_fragment"
                if node
                    .parent()
                    .is_some_and(|parent| parent.kind() == "template_string") =>
            {
                let value = &self.source[node.byte_range()];
                if value.len() > 2 && !value.chars().all(char::is_whitespace) {
                    strings.push(StringFingerprint {
                        context: self.classify_string(value),
                        value: value.to_owned(),
                    });
                }
            }
            "number" => {
                if let Ok(num) = self.source[node.byte_range()].parse::<i64>() {
                    // Special handling for common timer values
                    if matches!(num, 100 | 200 | 500 | 1000 | 2000 | 5000) {
                        constants.push(ConstantFingerprint {
                            value: ConstantValue::Duration(num as u64),
                        });
                    } else if !(-100..=100).contains(&num) {
                        // Only track non-trivial numbers
                        constants.push(ConstantFingerprint {
                            value: ConstantValue::Number(num),
                        });
                    }
                } else if self.source[node.byte_range()].parse::<f64>().is_ok() {
                    constants.push(ConstantFingerprint {
                        value: ConstantValue::Float(self.source[node.byte_range()].to_string()),
                    });
                }
            }
            "regex" => {
                let regex_str = &self.source[node.byte_range()];
                constants.push(ConstantFingerprint {
                    value: ConstantValue::Regex(regex_str.to_string()),
                });
            }
            "call_expression" => {
                if let Some(api_call) = self.extract_api_call(node) {
                    api_calls.push(api_call);
                }
            }
            _ => {}
        }

        // Recurse into children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if !matches!(child.kind(), "comment") {
                    self.extract_fingerprints_recursive(
                        child, strings, constants, api_calls, node_count,
                    );
                }

                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }

    fn extract_string_value(&self, node: Node) -> Option<String> {
        let text = &self.source[node.byte_range()];
        // Remove quotes
        if text.len() >= 2 {
            let inner = &text[1..text.len() - 1];
            // Basic unescape for common cases
            Some(
                inner
                    .replace("\\\"", "\"")
                    .replace("\\'", "'")
                    .replace("\\\\", "\\"),
            )
        } else {
            None
        }
    }

    fn classify_string(&self, s: &str) -> StringContext {
        let lower = s.to_lowercase();

        // Error messages
        if lower.contains("error")
            || lower.contains("fail")
            || lower.contains("exception")
            || lower.contains("invalid")
            || lower.contains("unable")
        {
            return StringContext::ErrorMessage;
        }

        // File paths
        if s.contains("~/")
            || s.contains("/.")
            || s.contains("\\")
            || s.ends_with(".js")
            || s.ends_with(".json")
            || s.ends_with(".md")
        {
            return StringContext::FilePath;
        }

        // API endpoints
        if s.starts_with("/") && (s.contains("/api") || s.chars().filter(|&c| c == '/').count() > 1)
        {
            return StringContext::ApiEndpoint;
        }

        // Command names (kebab-case)
        if s.contains("-") && s.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return StringContext::CommandName;
        }

        // Config keys
        if s.chars().all(|c| c.is_alphanumeric() || c == '_') && s.len() > 5 {
            return StringContext::ConfigKey;
        }

        StringContext::Regular
    }

    fn extract_api_call(&self, node: Node) -> Option<ApiCallFingerprint> {
        let func_node = node.child_by_field_name("function")?;

        let (object, method) = match func_node.kind() {
            "member_expression" => {
                let obj = func_node.child_by_field_name("object")?;
                let prop = func_node.child_by_field_name("property")?;

                let obj_text = &self.source[obj.byte_range()];
                let method_text = &self.source[prop.byte_range()];

                // Special handling for nested member expressions like process.env
                let full_obj = if obj.kind() == "member_expression" {
                    self.get_full_member_path(obj)
                } else {
                    obj_text.to_string()
                };

                (Some(full_obj), method_text.to_string())
            }
            "identifier" => {
                let method = &self.source[func_node.byte_range()];
                (None, method.to_string())
            }
            _ => return None,
        };

        // Skip minified method names
        if method.len() <= 2 && !matches!(method.as_str(), "fs" | "os") {
            return None;
        }

        // Extract first argument if it's a literal
        let first_arg = node.child_by_field_name("arguments").and_then(|args| {
            let mut cursor = args.walk();
            cursor.goto_first_child();
            loop {
                let child = cursor.node();
                match child.kind() {
                    "string" => return self.extract_string_value(child),
                    "number" => return Some(self.source[child.byte_range()].to_string()),
                    "," | "(" | ")" => {}
                    _ => return None,
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
            None
        });

        Some(ApiCallFingerprint {
            object,
            method,
            first_arg,
        })
    }

    fn get_full_member_path(&self, node: Node) -> String {
        let mut parts = Vec::new();
        let mut current = node;

        loop {
            if current.kind() == "member_expression" {
                if let Some(prop) = current.child_by_field_name("property") {
                    parts.push(self.source[prop.byte_range()].to_string());
                }
                if let Some(obj) = current.child_by_field_name("object") {
                    if obj.kind() == "member_expression" {
                        current = obj;
                        continue;
                    } else {
                        parts.push(self.source[obj.byte_range()].to_string());
                        break;
                    }
                }
            } else {
                parts.push(self.source[current.byte_range()].to_string());
                break;
            }
        }

        parts.reverse();
        parts.join(".")
    }
}

#[derive(Debug)]
pub struct RarityScorer {
    string_counts: HashMap<String, usize>,
    constant_counts: HashMap<ConstantValue, usize>,
    api_counts: HashMap<String, usize>,
}

impl Default for RarityScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl RarityScorer {
    pub fn new() -> Self {
        Self {
            string_counts: HashMap::new(),
            constant_counts: HashMap::new(),
            api_counts: HashMap::new(),
        }
    }

    pub fn add_fingerprint(&mut self, fp: &FunctionFingerprint) {
        for s in &fp.strings {
            *self.string_counts.entry(s.value.clone()).or_insert(0) += 1;
        }

        for c in &fp.constants {
            *self.constant_counts.entry(c.value.clone()).or_insert(0) += 1;
        }

        for api in &fp.api_calls {
            let key = format!("{:?}::{}", api.object, api.method);
            *self.api_counts.entry(key).or_insert(0) += 1;
        }
    }

    pub fn score_string(&self, s: &str) -> f64 {
        match self.string_counts.get(s) {
            Some(1) => 1.0,
            Some(2) => 0.7,
            Some(3..=5) => 0.4,
            Some(_) => 0.1,
            None => 0.0,
        }
    }

    pub fn score_constant(&self, c: &ConstantValue) -> f64 {
        match self.constant_counts.get(c) {
            Some(1) => 1.0,
            Some(2) => 0.6,
            Some(3..=5) => 0.3,
            Some(_) => 0.1,
            None => 0.0,
        }
    }

    pub fn score_api_call(&self, api: &ApiCallFingerprint) -> f64 {
        // Called tens of millions of times in the full-similarity phase, so the lookup key is
        // built into a reused thread-local buffer instead of a fresh String per call. The
        // `write!` uses the same format string as `add_fingerprint`, so the key is identical.
        API_KEY_BUF.with(|buf| {
            let mut key = buf.borrow_mut();
            key.clear();
            let _ = write!(key, "{:?}::{}", api.object, api.method);
            match self.api_counts.get(key.as_str()) {
                Some(1..=3) => 0.8,
                Some(4..=10) => 0.5,
                Some(_) => 0.2,
                None => 0.0,
            }
        })
    }
}

thread_local! {
    static API_KEY_BUF: RefCell<String> = const { RefCell::new(String::new()) };
}

pub fn calculate_fingerprint_similarity(
    fp1: &FunctionFingerprint,
    fp2: &FunctionFingerprint,
    scorer: &RarityScorer,
) -> (f64, usize) {
    let mut total_score = 0.0;
    let mut evidence_count = 0;
    // Match strings (highest weight).
    //
    // The original form carried a `HashSet<String>` of already-scored values, cloning a String
    // per match. That set can only ever suppress a later fp1 entry whose value was already
    // scored, and a value is scored exactly when it also occurs in fp2. So "already in the set"
    // is equivalent to "an earlier fp1 entry has the same value", which needs no allocation.
    // The dedup check runs after the fp2 lookup because it only matters for entries that match.
    for (i, s1) in fp1.strings.iter().enumerate() {
        if !fp2.strings.iter().any(|s2| s2.value == s1.value) {
            continue;
        }

        if fp1.strings[..i].iter().any(|prev| prev.value == s1.value) {
            continue;
        }

        let rarity = scorer.score_string(&s1.value);
        let context_weight = match s1.context {
            StringContext::ErrorMessage => 1.2,
            StringContext::FilePath => 1.1,
            StringContext::CommandName => 1.0,
            StringContext::ConfigKey => 0.9,
            StringContext::ApiEndpoint => 1.0,
            StringContext::Regular => 0.7,
        };

        total_score += rarity * context_weight;
        evidence_count += 1;
    }

    // Match constants (same dedup reasoning as strings)
    for (i, c1) in fp1.constants.iter().enumerate() {
        if !fp2.constants.iter().any(|c2| c2.value == c1.value) {
            continue;
        }

        if fp1.constants[..i].iter().any(|prev| prev.value == c1.value) {
            continue;
        }

        let rarity = scorer.score_constant(&c1.value);

        total_score += rarity * 0.8;
        evidence_count += 1;
    }

    // Match API calls. Deliberately no dedup: duplicate (object, method) keys contribute once
    // per (api1, api2) pair, each with its own arg_bonus. The rarity depends only on api1, so it
    // is computed at most once per api1 and reused for every api2 it matches; the added terms and
    // their order are unchanged.
    for api1 in &fp1.api_calls {
        let mut cached_rarity: Option<f64> = None;

        for api2 in &fp2.api_calls {
            if api1.object == api2.object && api1.method == api2.method {
                let rarity = *cached_rarity.get_or_insert_with(|| scorer.score_api_call(api1));
                // Bonus if first argument also matches
                let arg_bonus = if api1.first_arg == api2.first_arg && api1.first_arg.is_some() {
                    0.3
                } else {
                    0.0
                };
                total_score += rarity * 0.6 + arg_bonus;
                evidence_count += 1;
            }
        }
    }

    // Size compatibility factor
    let size_ratio = fp1.size.min(fp2.size) as f64 / fp1.size.max(fp2.size) as f64;
    let size_factor = if size_ratio > 0.7 {
        1.0
    } else {
        0.8 + 0.2 * size_ratio
    };

    let final_score = if evidence_count > 0 {
        (total_score / evidence_count as f64) * size_factor
    } else {
        0.0
    };

    (final_score, evidence_count)
}
