//! JSON Schema construction and validation for tool arguments and results.
//!
//! Every tool advertises an input schema and the dispatcher validates the
//! arguments against it before the tool runs, so a tool only ever sees values
//! of the declared shape. The validator implements an exact subset of JSON
//! Schema 2020-12; [`check_supported`] proves a schema stays inside it, so a
//! keyword the validator would silently ignore cannot ship.
//!
//! Validation messages are written for the model that must correct its call:
//! each names the argument by path, says what was expected and what arrived,
//! and all problems (up to a cap) are reported together.
//!
//! Supported keywords: `type`, `properties`, `required`,
//! `additionalProperties`, `items` (single schema), `enum`, `const`,
//! `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `minLength`,
//! `maxLength`, `minItems`, `maxItems`, `uniqueItems`, `minProperties` and
//! `maxProperties`. Annotation keywords are accepted and ignored.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::io::{self, Write};

use serde_json::{json, Map, Number, Value};

/// Deepest container nesting accepted in an instance or a schema.
const MAX_DEPTH: usize = 64;
/// Problems reported in one validation message.
const MAX_PROBLEMS: usize = 8;
/// Characters of any instance value echoed back to the model.
const ECHO_CHARS: usize = 80;
/// Enum values or declared property names listed in one message.
const MAX_LISTED: usize = 40;

const VALIDATION_KEYWORDS: &[&str] = &[
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "const",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "uniqueItems",
    "minProperties",
    "maxProperties",
];

const ANNOTATION_KEYWORDS: &[&str] = &[
    "description",
    "title",
    "default",
    "examples",
    "$schema",
    "x-mcp-header",
    "deprecated",
    "readOnly",
    "writeOnly",
    "format",
];

const TYPE_NAMES: &[&str] = &[
    "object", "array", "string", "integer", "number", "boolean", "null",
];

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for a JSON Schema `object`, for tool input and output schemas.
///
/// [`ObjectSchema::new`] produces a closed object (`additionalProperties:
/// false`), right for inputs. [`ObjectSchema::open`] omits that keyword, right
/// for outputs, where adding a field later must not break clients.
/// Properties serialise in sorted order so `tools/list` is deterministic;
/// `required` keeps declaration order.
#[derive(Debug, Clone)]
pub struct ObjectSchema {
    properties: Map<String, Value>,
    required: Vec<String>,
    additional: Option<bool>,
    description: Option<String>,
}

impl Default for ObjectSchema {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectSchema {
    /// A closed object schema: unknown properties are rejected.
    #[must_use]
    pub fn new() -> Self {
        Self {
            properties: Map::new(),
            required: Vec::new(),
            additional: Some(false),
            description: None,
        }
    }

    /// An open object schema that does not restrict additional properties.
    #[must_use]
    pub fn open() -> Self {
        Self {
            additional: None,
            ..Self::new()
        }
    }

    /// Explicitly allow additional properties (`additionalProperties: true`).
    #[must_use]
    pub fn allow_additional(mut self) -> Self {
        self.additional = Some(true);
        self
    }

    /// Set the description of the object itself.
    #[must_use]
    pub fn describe(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Add a property with an explicit schema fragment. Declaring a name again
    /// replaces the earlier declaration.
    #[must_use]
    pub fn prop(mut self, name: &str, schema: Value, required: bool) -> Self {
        self.required.retain(|n| n != name);
        if required {
            self.required.push(name.to_string());
        }
        self.properties.insert(name.to_string(), schema);
        self
    }

    /// Add a string property.
    #[must_use]
    pub fn string(self, name: &str, description: &str, required: bool) -> Self {
        self.prop(
            name,
            json!({"type": "string", "description": description}),
            required,
        )
    }

    /// Add a string property with a maximum length in characters.
    #[must_use]
    pub fn string_max(self, name: &str, description: &str, max_len: usize, required: bool) -> Self {
        self.prop(
            name,
            json!({"type": "string", "description": description, "maxLength": max_len}),
            required,
        )
    }

    /// Add an integer property.
    #[must_use]
    pub fn integer(self, name: &str, description: &str, required: bool) -> Self {
        self.prop(
            name,
            json!({"type": "integer", "description": description}),
            required,
        )
    }

    /// Add an integer property bounded to `min..=max`.
    #[must_use]
    pub fn integer_range(
        self,
        name: &str,
        description: &str,
        min: i64,
        max: i64,
        required: bool,
    ) -> Self {
        self.prop(
            name,
            json!({"type": "integer", "description": description, "minimum": min, "maximum": max}),
            required,
        )
    }

    /// Add an integer property with a lower bound.
    #[must_use]
    pub fn integer_min(self, name: &str, description: &str, min: i64, required: bool) -> Self {
        self.prop(
            name,
            json!({"type": "integer", "description": description, "minimum": min}),
            required,
        )
    }

    /// Add a number (integer or fractional) property.
    #[must_use]
    pub fn number(self, name: &str, description: &str, required: bool) -> Self {
        self.prop(
            name,
            json!({"type": "number", "description": description}),
            required,
        )
    }

    /// Add a boolean property.
    #[must_use]
    pub fn boolean(self, name: &str, description: &str, required: bool) -> Self {
        self.prop(
            name,
            json!({"type": "boolean", "description": description}),
            required,
        )
    }

    /// Add an optional boolean property that documents its `default`.
    #[must_use]
    pub fn boolean_default(self, name: &str, description: &str, default: bool) -> Self {
        self.boolean(name, description, false)
            .default_value(name, Value::Bool(default))
    }

    /// Add an array-of-strings property.
    #[must_use]
    pub fn string_array(self, name: &str, description: &str, required: bool) -> Self {
        self.prop(
            name,
            json!({"type": "array", "items": {"type": "string"}, "description": description}),
            required,
        )
    }

    /// Add an array-of-strings property with a maximum number of items.
    #[must_use]
    pub fn string_array_max(
        self,
        name: &str,
        description: &str,
        max_items: usize,
        required: bool,
    ) -> Self {
        self.prop(
            name,
            json!({
                "type": "array",
                "items": {"type": "string"},
                "description": description,
                "maxItems": max_items,
            }),
            required,
        )
    }

    /// Add a string property restricted to `values`.
    #[must_use]
    pub fn string_enum(
        self,
        name: &str,
        description: &str,
        values: &[&str],
        required: bool,
    ) -> Self {
        self.prop(
            name,
            json!({"type": "string", "description": description, "enum": values}),
            required,
        )
    }

    /// Add an object property whose values are all strings (environment
    /// variables, HTTP headers).
    #[must_use]
    pub fn string_map(self, name: &str, description: &str, required: bool) -> Self {
        self.prop(
            name,
            json!({
                "type": "object",
                "description": description,
                "additionalProperties": {"type": "string"},
            }),
            required,
        )
    }

    /// Add a string property that may also be `null`.
    #[must_use]
    pub fn nullable_string(self, name: &str, description: &str, required: bool) -> Self {
        self.prop(
            name,
            nullable(json!({"type": "string", "description": description})),
            required,
        )
    }

    /// Add an integer property that may also be `null`.
    #[must_use]
    pub fn nullable_integer(self, name: &str, description: &str, required: bool) -> Self {
        self.prop(
            name,
            nullable(json!({"type": "integer", "description": description})),
            required,
        )
    }

    /// Add a nested object property built with its own [`ObjectSchema`].
    #[must_use]
    pub fn object(
        self,
        name: &str,
        description: &str,
        nested: ObjectSchema,
        required: bool,
    ) -> Self {
        self.prop(name, nested.describe(description).build(), required)
    }

    /// Add an array property whose items are objects built with `item`.
    #[must_use]
    pub fn object_array(
        self,
        name: &str,
        description: &str,
        item: ObjectSchema,
        required: bool,
    ) -> Self {
        self.prop(
            name,
            json!({"type": "array", "description": description, "items": item.build()}),
            required,
        )
    }

    /// Record a `default` on an already declared property. Documentation
    /// only: validation never applies defaults.
    #[must_use]
    pub fn default_value(mut self, name: &str, value: Value) -> Self {
        match self.properties.get_mut(name).and_then(Value::as_object_mut) {
            Some(schema) => {
                schema.insert("default".to_string(), value);
            }
            None => debug_assert!(false, "default_value: '{name}' is not a declared property"),
        }
        self
    }

    /// Finish into a JSON Schema value.
    #[must_use]
    pub fn build(self) -> Value {
        let mut out = Map::new();
        out.insert("type".to_string(), json!("object"));
        if let Some(description) = self.description {
            out.insert("description".to_string(), Value::String(description));
        }
        out.insert("properties".to_string(), Value::Object(self.properties));
        out.insert("required".to_string(), json!(self.required));
        if let Some(additional) = self.additional {
            out.insert("additionalProperties".to_string(), Value::Bool(additional));
        }
        Value::Object(out)
    }
}

/// Make `schema` also accept `null`: `"type": "string"` becomes
/// `["string", "null"]`, and an `enum` gains a `null` member.
#[must_use]
pub fn nullable(mut schema: Value) -> Value {
    let Some(map) = schema.as_object_mut() else {
        return schema;
    };
    match map.get_mut("type") {
        Some(Value::String(t)) if t != "null" => {
            let t = std::mem::take(t);
            map.insert("type".to_string(), json!([t, "null"]));
        }
        Some(Value::Array(types)) if !types.iter().any(|t| t == "null") => {
            types.push(json!("null"));
        }
        _ => {}
    }
    if let Some(Value::Array(values)) = map.get_mut("enum") {
        if !values.iter().any(Value::is_null) {
            values.push(Value::Null);
        }
    }
    schema
}

// ---------------------------------------------------------------------------
// Value helpers shared with the typed accessors
// ---------------------------------------------------------------------------

/// The exact integer an `integer`-typed JSON number denotes, if it has one.
/// Accepts `3.0` and `1e3`; rejects fractions and anything outside i64/u64.
pub(crate) fn integer_of(n: &Number) -> Option<i128> {
    if let Some(i) = n.as_i64() {
        return Some(i128::from(i));
    }
    if let Some(u) = n.as_u64() {
        return Some(i128::from(u));
    }
    let f = n.as_f64()?;
    // 2^63 and 2^64 are exactly representable.
    let in_range = (-9_223_372_036_854_775_808.0..18_446_744_073_709_551_616.0).contains(&f);
    (f.is_finite() && f.fract() == 0.0 && in_range).then_some(f as i128)
}

pub(crate) fn integer_value(v: &Value) -> Option<i128> {
    match v {
        Value::Number(n) => integer_of(n),
        _ => None,
    }
}

/// Exact numeric comparison across i64, u64 and f64 representations.
fn cmp_numbers(a: &Number, b: &Number) -> Option<Ordering> {
    let int = |n: &Number| {
        n.as_i64()
            .map(i128::from)
            .or_else(|| n.as_u64().map(i128::from))
    };
    match (int(a), int(b)) {
        (Some(x), Some(y)) => Some(x.cmp(&y)),
        (Some(x), None) => cmp_int_float(x, b.as_f64()?),
        (None, Some(y)) => cmp_int_float(y, a.as_f64()?).map(Ordering::reverse),
        (None, None) => a.as_f64()?.partial_cmp(&b.as_f64()?),
    }
}

/// Compare an integer with magnitude at most 2^64 against a float.
fn cmp_int_float(i: i128, f: f64) -> Option<Ordering> {
    const LIMIT: f64 = 18_446_744_073_709_551_616.0;
    if f.is_nan() {
        return None;
    }
    if f >= LIMIT {
        return Some(Ordering::Less);
    }
    if f <= -LIMIT {
        return Some(Ordering::Greater);
    }
    let whole = f.trunc();
    match i.cmp(&(whole as i128)) {
        Ordering::Equal => {
            let rest = f - whole;
            Some(if rest > 0.0 {
                Ordering::Less
            } else if rest < 0.0 {
                Ordering::Greater
            } else {
                Ordering::Equal
            })
        }
        other => Some(other),
    }
}

/// JSON equality where `1` equals `1.0`. Callers bound the depth first.
fn json_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => cmp_numbers(x, y) == Some(Ordering::Equal),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| json_eq(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).is_some_and(|w| json_eq(v, w)))
        }
        _ => a == b,
    }
}

/// A canonical text form such that `json_eq` values produce equal strings.
fn canon(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => match integer_of(n) {
            Some(i) => out.push_str(&i.to_string()),
            None => out.push_str(&format!("{:?}", n.as_f64().unwrap_or_default())),
        },
        Value::String(s) => out.push_str(&serde_json::to_string(s).unwrap_or_default()),
        Value::Array(items) => {
            out.push('[');
            for item in items {
                canon(item, out);
                out.push(',');
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for key in keys {
                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push(':');
                if let Some(value) = map.get(key) {
                    canon(value, out);
                }
                out.push(',');
            }
            out.push('}');
        }
    }
}

/// Whether containers nest deeper than `limit`. Iterative, so it cannot
/// overflow the stack on hostile input.
fn exceeds_depth(root: &Value, limit: usize) -> bool {
    let mut stack = vec![(root, 0usize)];
    while let Some((v, depth)) = stack.pop() {
        match v {
            Value::Array(items) => {
                if depth + 1 > limit {
                    return true;
                }
                stack.extend(items.iter().map(|x| (x, depth + 1)));
            }
            Value::Object(map) => {
                if depth + 1 > limit {
                    return true;
                }
                stack.extend(map.values().map(|x| (x, depth + 1)));
            }
            _ => {}
        }
    }
    false
}

fn kind_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if integer_of(n).is_some() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Writer that keeps at most `limit` bytes and then fails, so echoing a huge
/// value never serialises more than a prefix of it.
struct Capped {
    buf: Vec<u8>,
    limit: usize,
    truncated: bool,
}

impl Write for Capped {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let room = self.limit.saturating_sub(self.buf.len());
        if data.len() > room {
            self.buf.extend(data.iter().copied().take(room));
            self.truncated = true;
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "echo limit reached",
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A value rendered as JSON and cut to at most [`ECHO_CHARS`] characters.
pub(crate) fn echo(v: &Value) -> String {
    let mut w = Capped {
        buf: Vec::new(),
        limit: ECHO_CHARS * 4,
        truncated: false,
    };
    // A failed write is the cap being reached, recorded in `truncated`.
    let _ = serde_json::to_writer(&mut w, v);
    let text = String::from_utf8_lossy(&w.buf);
    truncate_chars(&text, ECHO_CHARS, w.truncated)
}

fn truncate_chars(text: &str, max: usize, already_cut: bool) -> String {
    let mut out: String = text.chars().take(max).collect();
    if already_cut || text.chars().nth(max).is_some() {
        out.push('…');
    }
    out
}

/// `kind` plus the truncated value, e.g. `string "abc"`; just `null` for null.
pub(crate) fn describe_value(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        _ => format!("{} {}", kind_of(v), echo(v)),
    }
}

fn article(type_name: &str) -> &'static str {
    match type_name {
        "object" => "an object",
        "array" => "an array",
        "string" => "a string",
        "integer" => "an integer",
        "number" => "a number",
        "boolean" => "a boolean",
        "null" => "null",
        _ => "a value",
    }
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.len() > 64 || b.len() > 64 {
        return usize::MAX;
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let sub = prev.get(j).copied().unwrap_or(0) + usize::from(ca != cb);
            let del = prev.get(j + 1).copied().unwrap_or(0) + 1;
            let ins = cur.get(j).copied().unwrap_or(0) + 1;
            cur.push(sub.min(del).min(ins));
        }
        prev = cur;
    }
    prev.last().copied().unwrap_or(0)
}

fn normalize_name(s: &str) -> String {
    s.chars()
        .filter(|c| *c != '_' && *c != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

/// The candidate that differs from `input` only by case, `_` or `-`, or else
/// the nearest one within edit distance 2.
fn closest<'a>(input: &str, candidates: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let norm = normalize_name(input);
    let lower = input.to_lowercase();
    let mut best: Option<(&str, usize)> = None;
    for c in candidates {
        let d = if !norm.is_empty() && normalize_name(c) == norm {
            0
        } else {
            let d = edit_distance(&lower, &c.to_lowercase());
            let shorter = input.chars().count().min(c.chars().count());
            if d > 2 || d >= shorter {
                continue;
            }
            d
        };
        if best.is_none_or(|(_, bd)| d < bd) {
            best = Some((c, d));
        }
    }
    best.map(|(c, _)| c)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate tool arguments against `schema`.
///
/// On failure the message names every problem found (up to a cap), written
/// for the model to correct its call. Defaults are not applied.
pub fn validate(schema: &Value, instance: &Value) -> Result<(), String> {
    validate_as("args", "the arguments", schema, instance)
}

/// [`validate`] with a custom root name and subject, e.g. for checking a
/// structured result as `("result", "the structured result")`.
pub fn validate_as(
    root: &str,
    subject: &str,
    schema: &Value,
    instance: &Value,
) -> Result<(), String> {
    if exceeds_depth(instance, MAX_DEPTH) {
        return Err(format!(
            "{root} is nested more than {MAX_DEPTH} levels deep; flatten the structure"
        ));
    }
    let mut v = Validator::default();
    let mut path = root.to_string();
    v.node(schema, instance, &mut path);
    v.finish(subject)
}

#[derive(Default)]
struct Validator {
    problems: Vec<String>,
    overflow: bool,
}

/// Append `key` to a path; returns the length to truncate back to.
fn push_key(path: &mut String, key: &str) -> usize {
    let mark = path.len();
    let plain = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '$'));
    if plain {
        path.push('.');
        path.push_str(&truncate_chars(key, 40, false));
    } else {
        let shown = truncate_chars(key, 40, false);
        path.push('[');
        path.push_str(&serde_json::to_string(&shown).unwrap_or_default());
        path.push(']');
    }
    mark
}

fn push_index(path: &mut String, index: usize) -> usize {
    let mark = path.len();
    path.push_str(&format!("[{index}]"));
    mark
}

impl Validator {
    fn push(&mut self, problem: String) {
        if self.problems.len() >= MAX_PROBLEMS {
            self.overflow = true;
        } else {
            self.problems.push(problem);
        }
    }

    fn bad_schema(&mut self, path: &str, what: &str) {
        self.push(format!(
            "{path}: the tool's own schema is malformed ({what}); this is a server bug, not a mistake in the call"
        ));
    }

    fn finish(self, subject: &str) -> Result<(), String> {
        if self.problems.is_empty() {
            return Ok(());
        }
        let n = self.problems.len();
        let head = if self.overflow {
            format!("{MAX_PROBLEMS} or more problems with {subject} (showing the first {MAX_PROBLEMS}):")
        } else if n == 1 {
            format!("1 problem with {subject}:")
        } else {
            format!("{n} problems with {subject}:")
        };
        let mut out = head;
        for p in &self.problems {
            out.push_str("\n- ");
            out.push_str(p);
        }
        Err(out)
    }

    fn node(&mut self, schema: &Value, inst: &Value, path: &mut String) {
        if self.overflow {
            return;
        }
        let map = match schema {
            Value::Bool(true) => return,
            Value::Bool(false) => {
                self.push(format!("{path}: no value is allowed here"));
                return;
            }
            Value::Object(m) => m,
            _ => {
                self.bad_schema(path, "a schema must be an object or a boolean");
                return;
            }
        };

        let type_ok = match map.get("type") {
            None => true,
            Some(t) if type_names(t).is_some() => type_accepts(t, inst),
            Some(_) => {
                self.bad_schema(path, "\"type\" must be a type name or an array of them");
                return;
            }
        };

        if let Some(allowed) = map.get("enum") {
            let Value::Array(values) = allowed else {
                self.bad_schema(path, "\"enum\" must be an array");
                return;
            };
            if !values.iter().any(|v| json_eq(v, inst)) {
                self.push(enum_problem(path, values, inst));
                return;
            }
        }
        if !type_ok {
            self.push(type_problem(path, map.get("type"), inst));
            return;
        }
        if let Some(expected) = map.get("const") {
            if !json_eq(expected, inst) {
                self.push(format!(
                    "{path}: must be exactly {}; got {}",
                    echo(expected),
                    describe_value(inst)
                ));
                return;
            }
        }

        match inst {
            Value::Number(n) => self.number(map, n, path),
            Value::String(s) => self.string(map, s, path),
            Value::Array(a) => self.array(map, a, path),
            Value::Object(o) => self.object(map, o, path),
            _ => {}
        }
    }

    fn number(&mut self, map: &Map<String, Value>, n: &Number, path: &str) {
        let rules: [(&str, &[Ordering], &str); 4] = [
            ("minimum", &[Ordering::Greater, Ordering::Equal], "at least"),
            ("maximum", &[Ordering::Less, Ordering::Equal], "at most"),
            ("exclusiveMinimum", &[Ordering::Greater], "greater than"),
            ("exclusiveMaximum", &[Ordering::Less], "less than"),
        ];
        for (keyword, accepted, phrase) in rules {
            let Some(bound) = map.get(keyword) else {
                continue;
            };
            let Value::Number(bound) = bound else {
                self.bad_schema(path, &format!("\"{keyword}\" must be a number"));
                continue;
            };
            let ok = cmp_numbers(n, bound).is_some_and(|o| accepted.contains(&o));
            if !ok {
                self.push(format!("{path}: must be {phrase} {bound}; got {n}"));
            }
        }
    }

    fn size_bound(&mut self, map: &Map<String, Value>, keyword: &str, path: &str) -> Option<u64> {
        let value = map.get(keyword)?;
        let bound = integer_value(value).and_then(|i| u64::try_from(i).ok());
        if bound.is_none() {
            self.bad_schema(
                path,
                &format!("\"{keyword}\" must be a non-negative integer"),
            );
        }
        bound
    }

    fn string(&mut self, map: &Map<String, Value>, s: &str, path: &str) {
        let min = self.size_bound(map, "minLength", path);
        let max = self.size_bound(map, "maxLength", path);
        if min.is_none() && max.is_none() {
            return;
        }
        let len = s.chars().count() as u64;
        if let Some(min) = min.filter(|m| len < *m) {
            self.push(format!(
                "{path}: must be at least {min} characters long; got {len}"
            ));
        }
        if let Some(max) = max.filter(|m| len > *m) {
            self.push(format!(
                "{path}: must be at most {max} characters long; got {len}"
            ));
        }
    }

    fn array(&mut self, map: &Map<String, Value>, items: &[Value], path: &mut String) {
        let len = items.len() as u64;
        if let Some(min) = self.size_bound(map, "minItems", path).filter(|m| len < *m) {
            self.push(format!(
                "{path}: must contain at least {min} items; got {len}"
            ));
        }
        if let Some(max) = self.size_bound(map, "maxItems", path).filter(|m| len > *m) {
            self.push(format!(
                "{path}: must contain at most {max} items; got {len}"
            ));
        }
        match map.get("uniqueItems") {
            None | Some(Value::Bool(false)) => {}
            Some(Value::Bool(true)) => self.unique_items(items, path),
            Some(_) => self.bad_schema(path, "\"uniqueItems\" must be a boolean"),
        }
        if let Some(item_schema) = map.get("items") {
            for (i, item) in items.iter().enumerate() {
                if self.overflow {
                    break;
                }
                let mark = push_index(path, i);
                self.node(item_schema, item, path);
                path.truncate(mark);
            }
        }
    }

    fn unique_items(&mut self, items: &[Value], path: &str) {
        let mut seen: HashMap<String, usize> = HashMap::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            let mut key = String::new();
            canon(item, &mut key);
            if let Some(first) = seen.insert(key, i) {
                self.push(format!(
                    "{path}[{i}]: duplicates {path}[{first}]; the items must be unique"
                ));
                return;
            }
        }
    }

    fn object(&mut self, map: &Map<String, Value>, obj: &Map<String, Value>, path: &mut String) {
        let len = obj.len() as u64;
        if let Some(min) = self
            .size_bound(map, "minProperties", path)
            .filter(|m| len < *m)
        {
            self.push(format!(
                "{path}: must have at least {min} properties; got {len}"
            ));
        }
        if let Some(max) = self
            .size_bound(map, "maxProperties", path)
            .filter(|m| len > *m)
        {
            self.push(format!(
                "{path}: must have at most {max} properties; got {len}"
            ));
        }

        let declared = match map.get("properties") {
            None => None,
            Some(Value::Object(p)) => Some(p),
            Some(_) => {
                self.bad_schema(path, "\"properties\" must be an object");
                return;
            }
        };

        match map.get("required") {
            None => {}
            Some(Value::Array(names)) => {
                for name in names {
                    let Some(name) = name.as_str() else {
                        self.bad_schema(path, "\"required\" must list strings");
                        break;
                    };
                    if !obj.contains_key(name) {
                        let mark = push_key(path, name);
                        let expected = declared
                            .and_then(|p| p.get(name))
                            .and_then(|s| s.get("type"))
                            .map(expected_phrase)
                            .map(|e| format!(" (expected {e})"))
                            .unwrap_or_default();
                        self.push(format!("{path}: required property is missing{expected}"));
                        path.truncate(mark);
                    }
                }
            }
            Some(_) => self.bad_schema(path, "\"required\" must be an array"),
        }

        if let Some(declared) = declared {
            for (name, sub) in declared {
                if self.overflow {
                    return;
                }
                if let Some(value) = obj.get(name) {
                    let mark = push_key(path, name);
                    self.node(sub, value, path);
                    path.truncate(mark);
                }
            }
        }

        let additional = map.get("additionalProperties");
        if matches!(additional, None | Some(Value::Bool(true))) {
            return;
        }
        let mut listed = false;
        for (key, value) in obj {
            if self.overflow {
                return;
            }
            if declared.is_some_and(|p| p.contains_key(key)) {
                continue;
            }
            let mark = push_key(path, key);
            match additional {
                Some(Value::Bool(false)) => {
                    let names = declared.map(|p| p.keys().map(String::as_str));
                    let problem = unknown_problem(path, key, names, &mut listed);
                    self.push(problem);
                }
                Some(schema) => self.node(schema, value, path),
                None => {}
            }
            path.truncate(mark);
        }
    }
}

fn unknown_problem<'a>(
    path: &str,
    key: &str,
    declared: Option<impl Iterator<Item = &'a str> + Clone>,
    listed: &mut bool,
) -> String {
    let Some(declared) = declared.filter(|d| d.clone().next().is_some()) else {
        return format!("{path}: unknown property; this object accepts no properties");
    };
    let mut line = format!("{path}: unknown property");
    if let Some(near) = closest(key, declared.clone()) {
        line.push_str(&format!("; did you mean \"{near}\"?"));
    }
    if !*listed {
        *listed = true;
        let names: Vec<&str> = declared.collect();
        let shown: Vec<&str> = names.iter().copied().take(MAX_LISTED).collect();
        line.push_str(&format!(" Declared properties: {}", shown.join(", ")));
        if names.len() > shown.len() {
            line.push_str(&format!(", and {} more", names.len() - shown.len()));
        }
    }
    line
}

/// The type names of a well-formed `type` keyword.
fn type_names(t: &Value) -> Option<Vec<&str>> {
    let names: Vec<&str> = match t {
        Value::String(s) => vec![s.as_str()],
        Value::Array(a) if !a.is_empty() => a.iter().map(Value::as_str).collect::<Option<_>>()?,
        _ => return None,
    };
    names
        .iter()
        .all(|n| TYPE_NAMES.contains(n))
        .then_some(names)
}

fn type_accepts(t: &Value, inst: &Value) -> bool {
    let one = |name: &str| match (name, inst) {
        ("object", Value::Object(_))
        | ("array", Value::Array(_))
        | ("string", Value::String(_))
        | ("boolean", Value::Bool(_))
        | ("null", Value::Null)
        | ("number", Value::Number(_)) => true,
        ("integer", Value::Number(n)) => integer_of(n).is_some(),
        _ => false,
    };
    match t {
        Value::String(s) => one(s),
        Value::Array(a) => a.iter().filter_map(Value::as_str).any(one),
        _ => false,
    }
}

fn expected_phrase(t: &Value) -> String {
    match t {
        Value::String(s) => article(s).to_string(),
        Value::Array(a) => {
            let parts: Vec<&str> = a.iter().filter_map(Value::as_str).map(article).collect();
            match parts.split_last() {
                Some((last, rest)) if !rest.is_empty() => {
                    format!("{} or {last}", rest.join(", "))
                }
                Some((last, _)) => (*last).to_string(),
                None => "a value".to_string(),
            }
        }
        _ => "a value".to_string(),
    }
}

fn type_problem(path: &str, t: Option<&Value>, inst: &Value) -> String {
    let expected = t.map(expected_phrase).unwrap_or_default();
    format!("{path}: expected {expected}; got {}", describe_value(inst))
}

fn enum_problem(path: &str, values: &[Value], inst: &Value) -> String {
    let shown: Vec<String> = values.iter().take(MAX_LISTED).map(echo).collect();
    let mut allowed = shown.join(", ");
    if values.len() > shown.len() {
        allowed.push_str(&format!(", and {} more", values.len() - shown.len()));
    }
    let hint = inst
        .as_str()
        .and_then(|s| closest(s, values.iter().filter_map(Value::as_str)))
        .map(|near| format!(" (did you mean \"{near}\"?)"))
        .unwrap_or_default();
    format!(
        "{path}: must be one of {allowed}; got {}{hint}",
        describe_value(inst)
    )
}

// ---------------------------------------------------------------------------
// Schema checks
// ---------------------------------------------------------------------------

/// Check that `schema` uses only keywords [`validate`] implements, each with a
/// well-formed value. The error names the first offender.
pub fn check_supported(schema: &Value) -> Result<(), String> {
    if exceeds_depth(schema, MAX_DEPTH) {
        return Err(format!(
            "schema is nested more than {MAX_DEPTH} levels deep"
        ));
    }
    supported_node(schema, &mut String::from("#"))
}

fn pointer_push(ptr: &mut String, segment: &str) -> usize {
    let mark = ptr.len();
    ptr.push('/');
    ptr.push_str(&segment.replace('~', "~0").replace('/', "~1"));
    mark
}

fn supported_node(schema: &Value, ptr: &mut String) -> Result<(), String> {
    let map = match schema {
        Value::Bool(_) => return Ok(()),
        Value::Object(m) => m,
        _ => return Err(format!("schema at {ptr}: must be an object or a boolean")),
    };
    let bad = |ptr: &str, keyword: &str, want: &str| -> Result<(), String> {
        Err(format!("schema at {ptr}: \"{keyword}\" must be {want}"))
    };
    for (keyword, value) in map {
        match keyword.as_str() {
            "type" => {
                let distinct = type_names(value)
                    .is_some_and(|n| n.iter().collect::<HashSet<_>>().len() == n.len());
                if !distinct {
                    return bad(
                        ptr,
                        "type",
                        "a JSON type name or a non-empty array of distinct type names",
                    );
                }
            }
            "properties" => {
                let Value::Object(props) = value else {
                    return bad(ptr, "properties", "an object of schemas");
                };
                for (name, sub) in props {
                    let mark = pointer_push(ptr, "properties");
                    pointer_push(ptr, name);
                    let r = supported_node(sub, ptr);
                    ptr.truncate(mark);
                    r?;
                }
            }
            "required" => {
                let names: Option<Vec<&str>> = match value {
                    Value::Array(a) => a.iter().map(Value::as_str).collect(),
                    _ => None,
                };
                match names {
                    Some(n) if n.iter().collect::<HashSet<_>>().len() == n.len() => {}
                    _ => return bad(ptr, "required", "an array of distinct strings"),
                }
            }
            "additionalProperties" | "items" => match value {
                Value::Bool(_) | Value::Object(_) => {
                    let mark = pointer_push(ptr, keyword);
                    let r = supported_node(value, ptr);
                    ptr.truncate(mark);
                    r?;
                }
                Value::Array(_) if keyword == "items" => {
                    return Err(format!(
                        "schema at {ptr}: the array form of \"items\" (tuple validation) is not supported"
                    ))
                }
                _ => return bad(ptr, keyword, "a schema"),
            },
            "enum" => {
                if !value.is_array() {
                    return bad(ptr, "enum", "an array");
                }
            }
            "const" => {}
            "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" => {
                if !value.is_number() {
                    return bad(ptr, keyword, "a number");
                }
            }
            "minLength" | "maxLength" | "minItems" | "maxItems" | "minProperties"
            | "maxProperties" => {
                if !integer_value(value).is_some_and(|i| i >= 0) {
                    return bad(ptr, keyword, "a non-negative integer");
                }
            }
            "uniqueItems" => {
                if !value.is_boolean() {
                    return bad(ptr, "uniqueItems", "a boolean");
                }
            }
            other if ANNOTATION_KEYWORDS.contains(&other) => {}
            other => {
                return Err(format!(
                    "schema at {ptr}: keyword \"{other}\" is not implemented by the validator (supported: {})",
                    VALIDATION_KEYWORDS.join(", ")
                ))
            }
        }
    }
    Ok(())
}

/// Check an input schema against what MCP requires of one, on top of
/// [`check_supported`]: an object root, every `required` name declared, a
/// non-empty description on every property, non-empty unique `enum` arrays,
/// and well-formed, unique `x-mcp-header` annotations.
pub fn check_input_schema(schema: &Value) -> Result<(), String> {
    check_supported(schema)?;
    let is_object_root = schema
        .get("type")
        .is_some_and(|t| t.as_str() == Some("object"));
    if !is_object_root {
        return Err("the input schema's root must have \"type\": \"object\"".to_string());
    }
    let mut headers = HashMap::new();
    input_node(schema, &mut String::from("#"), true, &mut headers)
}

fn is_header_token(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
}

fn input_node(
    schema: &Value,
    ptr: &mut String,
    properties_only: bool,
    headers: &mut HashMap<String, String>,
) -> Result<(), String> {
    let Value::Object(map) = schema else {
        return Ok(());
    };
    let declared = map.get("properties").and_then(Value::as_object);

    if let Some(names) = map.get("required").and_then(Value::as_array) {
        for name in names.iter().filter_map(Value::as_str) {
            if !declared.is_some_and(|p| p.contains_key(name)) {
                return Err(format!(
                    "schema at {ptr}: required property \"{name}\" is not declared in \"properties\""
                ));
            }
        }
    }

    if let Some(values) = map.get("enum").and_then(Value::as_array) {
        if values.is_empty() {
            return Err(format!("schema at {ptr}: \"enum\" must not be empty"));
        }
        let mut seen = HashSet::new();
        for v in values {
            let mut key = String::new();
            canon(v, &mut key);
            if !seen.insert(key) {
                return Err(format!(
                    "schema at {ptr}: \"enum\" lists {} more than once",
                    echo(v)
                ));
            }
        }
    }

    if let Some(header) = map.get("x-mcp-header") {
        let Some(name) = header.as_str().filter(|h| is_header_token(h)) else {
            return Err(format!(
                "schema at {ptr}: \"x-mcp-header\" must be a non-empty HTTP header token (letters, digits and !#$%&'*+-.^_`|~)"
            ));
        };
        let scalar = map
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|t| matches!(t, "string" | "integer" | "boolean"));
        if !scalar {
            return Err(format!(
                "schema at {ptr}: \"x-mcp-header\" is only allowed on a property of type string, integer or boolean"
            ));
        }
        if !properties_only {
            return Err(format!(
                "schema at {ptr}: \"x-mcp-header\" is only allowed on properties reachable through \"properties\" alone, not inside arrays or additionalProperties"
            ));
        }
        if let Some(other) = headers.insert(name.to_ascii_lowercase(), ptr.clone()) {
            return Err(format!(
                "schema at {ptr}: \"x-mcp-header\" value \"{name}\" duplicates the one at {other} (header names are case-insensitive)"
            ));
        }
    }

    if let Some(props) = declared {
        for (name, sub) in props {
            let mark = pointer_push(ptr, "properties");
            pointer_push(ptr, name);
            let described = sub
                .get("description")
                .and_then(Value::as_str)
                .is_some_and(|d| !d.trim().is_empty());
            let result = if described {
                input_node(sub, ptr, properties_only, headers)
            } else {
                Err(format!(
                    "schema at {ptr}: property \"{name}\" needs a non-empty \"description\" (the model reads it)"
                ))
            };
            ptr.truncate(mark);
            result?;
        }
    }
    for keyword in ["items", "additionalProperties"] {
        if let Some(sub) = map.get(keyword).filter(|s| s.is_object()) {
            let mark = pointer_push(ptr, keyword);
            let result = input_node(sub, ptr, false, headers);
            ptr.truncate(mark);
            result?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(schema: &Value, inst: &Value) -> String {
        validate(schema, inst).expect_err("expected a validation failure")
    }

    fn problem_lines(message: &str) -> Vec<&str> {
        message.lines().skip(1).collect()
    }

    fn parse(text: &str) -> Value {
        serde_json::from_str(text).unwrap()
    }

    fn nested_arrays(depth: usize) -> Value {
        let mut v = json!(1);
        for _ in 0..depth {
            v = json!([v]);
        }
        v
    }

    // --- builder ---------------------------------------------------------

    #[test]
    fn builder_shape_is_closed_by_default() {
        let s = ObjectSchema::new()
            .string("path", "the path", true)
            .boolean("recursive", "recurse", false)
            .build();
        assert_eq!(s["type"], "object");
        assert_eq!(s["required"], json!(["path"]));
        assert_eq!(s["additionalProperties"], json!(false));
        assert_eq!(s["properties"]["path"]["type"], "string");
        assert_eq!(s["properties"]["recursive"]["description"], "recurse");
    }

    #[test]
    fn required_keeps_declaration_order_and_properties_are_sorted() {
        let s = ObjectSchema::new()
            .string("zeta", "z", true)
            .string("alpha", "a", true)
            .string("mid", "m", false)
            .string("beta", "b", true)
            .build();
        assert_eq!(s["required"], json!(["zeta", "alpha", "beta"]));
        let keys: Vec<&String> = s["properties"].as_object().unwrap().keys().collect();
        assert_eq!(keys, ["alpha", "beta", "mid", "zeta"]);
    }

    #[test]
    fn build_is_independent_of_property_declaration_order() {
        let a = ObjectSchema::new()
            .string("x", "x", false)
            .string("y", "y", false);
        let b = ObjectSchema::new()
            .string("y", "y", false)
            .string("x", "x", false);
        assert_eq!(a.build().to_string(), b.build().to_string());
    }

    #[test]
    fn open_omits_additional_properties_and_allow_additional_sets_true() {
        let open = ObjectSchema::open().string("a", "a", false).build();
        assert!(open.get("additionalProperties").is_none());
        let any = ObjectSchema::new().allow_additional().build();
        assert_eq!(any["additionalProperties"], json!(true));
    }

    #[test]
    fn bounded_and_typed_builders_emit_expected_fragments() {
        let s = ObjectSchema::new()
            .integer_range("n", "n", 1, 10, false)
            .integer_min("m", "m", 0, false)
            .string_max("name", "name", 64, true)
            .number("ratio", "ratio", false)
            .string_array_max("args", "args", 100, false)
            .string_enum("mode", "mode", &["a", "b"], false)
            .string_map("env", "env", false)
            .boolean_default("force", "force", true)
            .build();
        let p = &s["properties"];
        assert_eq!(
            p["n"],
            json!({"type":"integer","description":"n","minimum":1,"maximum":10})
        );
        assert_eq!(p["m"]["minimum"], json!(0));
        assert_eq!(p["name"]["maxLength"], json!(64));
        assert_eq!(p["ratio"]["type"], "number");
        assert_eq!(p["args"]["maxItems"], json!(100));
        assert_eq!(p["mode"]["enum"], json!(["a", "b"]));
        assert_eq!(p["env"]["additionalProperties"], json!({"type":"string"}));
        assert_eq!(p["force"]["default"], json!(true));
        assert_eq!(s["required"], json!(["name"]));
    }

    #[test]
    fn default_value_is_documentation_only() {
        let s = ObjectSchema::new()
            .integer("n", "n", false)
            .default_value("n", json!(5))
            .build();
        assert_eq!(s["properties"]["n"]["default"], json!(5));
        validate(&s, &json!({})).unwrap();
    }

    #[test]
    fn redeclaring_a_property_replaces_it_and_its_required_flag() {
        let s = ObjectSchema::new()
            .string("a", "first", true)
            .integer("a", "second", false)
            .build();
        assert_eq!(s["properties"]["a"]["type"], "integer");
        assert_eq!(s["required"], json!([]));
    }

    #[test]
    fn nullable_widens_type_and_enum_once() {
        let n = nullable(json!({"type": "string", "enum": ["a"]}));
        assert_eq!(n["type"], json!(["string", "null"]));
        assert_eq!(n["enum"], json!(["a", null]));
        assert_eq!(nullable(n.clone()), n);
        assert_eq!(
            nullable(json!({"type": ["string", "integer"]}))["type"],
            json!(["string", "integer", "null"])
        );
        assert_eq!(nullable(json!("not an object")), json!("not an object"));
    }

    #[test]
    fn output_schema_with_nullable_fields_and_object_arrays_validates() {
        let schema = ObjectSchema::open()
            .nullable_string("branch", "current branch", true)
            .nullable_integer("exitCode", "exit code", true)
            .object_array(
                "entries",
                "entries",
                ObjectSchema::open()
                    .string("name", "n", true)
                    .integer("size", "s", false),
                true,
            )
            .object(
                "meta",
                "meta",
                ObjectSchema::open().boolean("ok", "ok", true),
                false,
            )
            .build();
        validate(
            &schema,
            &json!({"branch": null, "exitCode": 0, "entries": [{"name": "a", "size": 3, "extra": 1}], "meta": {"ok": true}, "future": 1}),
        )
        .unwrap();
        let e = err(
            &schema,
            &json!({"branch": 5, "exitCode": null, "entries": [{"size": 1}]}),
        );
        assert!(
            e.contains("args.branch: expected a string or null; got integer 5"),
            "{e}"
        );
        assert!(
            e.contains("args.entries[0].name: required property is missing"),
            "{e}"
        );
        assert_eq!(schema["properties"]["meta"]["description"], "meta");
    }

    #[test]
    fn built_input_schema_passes_the_input_checks() {
        let s = ObjectSchema::new()
            .string("program", "the program", true)
            .string_enum("mode", "mode", &["a", "b"], false)
            .string_map("env", "environment", false)
            .object(
                "opts",
                "options",
                ObjectSchema::new().boolean("x", "x", false),
                false,
            )
            .build();
        check_input_schema(&s).unwrap();
    }

    // --- types -----------------------------------------------------------

    #[test]
    fn each_type_accepts_and_rejects() {
        let cases = [
            ("object", json!({}), json!([])),
            ("array", json!([]), json!({})),
            ("string", json!("s"), json!(1)),
            ("integer", json!(3), json!("3")),
            ("number", json!(1.5), json!(true)),
            ("boolean", json!(false), json!(null)),
            ("null", json!(null), json!(0)),
        ];
        for (ty, good, bad) in cases {
            let schema = json!({"type": ty});
            validate(&schema, &good).unwrap_or_else(|e| panic!("{ty}: {e}"));
            assert!(validate(&schema, &bad).is_err(), "{ty} should reject {bad}");
        }
    }

    #[test]
    fn integer_type_edge_cases() {
        let schema = json!({"type": "integer"});
        for text in [
            "3.0",
            "1e3",
            "-0.0",
            "0",
            "-9223372036854775808",
            "18446744073709551615",
            "9223372036854775807",
        ] {
            validate(&schema, &parse(text)).unwrap_or_else(|e| panic!("{text}: {e}"));
        }
        for text in [
            "1.5",
            "1e300",
            "18446744073709551616",
            "-9223372036854777856.0",
            "0.1",
        ] {
            assert!(
                validate(&schema, &parse(text)).is_err(),
                "{text} is not an integer"
            );
        }
        validate(&json!({"type": "number"}), &parse("1e300")).unwrap();
        validate(&json!({"type": "number"}), &parse("-0.0")).unwrap();
    }

    #[test]
    fn type_array_accepts_any_listed_type() {
        let schema = json!({"type": ["string", "null"]});
        validate(&schema, &json!("a")).unwrap();
        validate(&schema, &json!(null)).unwrap();
        let e = err(&schema, &json!(4));
        assert!(
            e.contains("expected a string or null; got integer 4"),
            "{e}"
        );
    }

    #[test]
    fn type_mismatch_message_has_path_expected_and_received() {
        let schema = ObjectSchema::new()
            .integer("timeoutSecs", "t", false)
            .build();
        let e = err(&schema, &json!({"timeoutSecs": "ten"}));
        assert_eq!(
            e,
            "1 problem with the arguments:\n- args.timeoutSecs: expected an integer; got string \"ten\""
        );
        let e = err(&schema, &json!({"timeoutSecs": 1.5}));
        assert!(e.contains("got number 1.5"), "{e}");
        let e = err(&schema, &json!({"timeoutSecs": null}));
        assert!(e.contains("expected an integer; got null"), "{e}");
        let e = err(&schema, &json!([1]));
        assert!(e.contains("args: expected an object; got array [1]"), "{e}");
    }

    // --- object keywords -------------------------------------------------

    #[test]
    fn required_property_missing_names_path_and_type() {
        let schema = ObjectSchema::new().string("path", "p", true).build();
        let e = err(&schema, &json!({}));
        assert!(
            e.contains("args.path: required property is missing (expected a string)"),
            "{e}"
        );
    }

    #[test]
    fn unknown_property_lists_declared_names_and_suggests() {
        let schema = ObjectSchema::new()
            .string("path", "p", true)
            .integer("timeoutSecs", "t", false)
            .build();
        let e = err(&schema, &json!({"path": "a", "timeout_secs": 5}));
        assert!(e.contains("args.timeout_secs: unknown property"), "{e}");
        assert!(e.contains("did you mean \"timeoutSecs\"?"), "{e}");
        assert!(e.contains("Declared properties: path, timeoutSecs"), "{e}");
    }

    #[test]
    fn suggestions_cover_case_distance_and_refuse_unrelated_names() {
        let schema = ObjectSchema::new()
            .string("path", "p", false)
            .string("recursive", "r", false)
            .build();
        assert!(err(&schema, &json!({"PATH": "x"})).contains("did you mean \"path\"?"));
        assert!(err(&schema, &json!({"pth": "x"})).contains("did you mean \"path\"?"));
        assert!(err(&schema, &json!({"paht": "x"})).contains("did you mean \"path\"?"));
        assert!(!err(&schema, &json!({"zzzzzz": "x"})).contains("did you mean"));
        let short = ObjectSchema::new().string("id", "i", false).build();
        assert!(!err(&short, &json!({"to": 1})).contains("did you mean"));
    }

    #[test]
    fn declared_properties_are_listed_once_for_several_unknowns() {
        let schema = ObjectSchema::new().string("path", "p", false).build();
        let e = err(&schema, &json!({"a": 1, "b": 2}));
        assert_eq!(e.matches("Declared properties").count(), 1, "{e}");
        assert_eq!(problem_lines(&e).len(), 2);
    }

    #[test]
    fn empty_object_schema_says_no_properties_are_accepted() {
        let e = err(&ObjectSchema::new().build(), &json!({"x": 1}));
        assert!(e.contains("accepts no properties"), "{e}");
    }

    #[test]
    fn additional_properties_schema_applies_to_undeclared_keys() {
        let schema = ObjectSchema::new().string_map("env", "e", false).build();
        validate(&schema, &json!({"env": {"A": "1"}})).unwrap();
        let e = err(&schema, &json!({"env": {"FOO": 1, "BAR": "ok"}}));
        assert!(
            e.contains("args.env.FOO: expected a string; got integer 1"),
            "{e}"
        );
        assert!(!e.contains("BAR"), "{e}");
    }

    #[test]
    fn open_objects_allow_anything_extra() {
        validate(
            &json!({"type": "object", "properties": {"a": {"type": "string"}}}),
            &json!({"a": "x", "b": [1]}),
        )
        .unwrap();
        validate(
            &json!({"type": "object", "additionalProperties": true}),
            &json!({"b": 1}),
        )
        .unwrap();
    }

    #[test]
    fn property_counts_are_bounded() {
        let schema = json!({"type": "object", "minProperties": 1, "maxProperties": 2});
        validate(&schema, &json!({"a": 1})).unwrap();
        assert!(err(&schema, &json!({})).contains("at least 1 properties; got 0"));
        assert!(
            err(&schema, &json!({"a": 1, "b": 2, "c": 3})).contains("at most 2 properties; got 3")
        );
    }

    #[test]
    fn odd_keys_are_quoted_in_paths() {
        let schema = json!({"type": "object", "additionalProperties": {"type": "integer"}});
        let e = err(&schema, &json!({"a.b": "x", "ok-1": "y"}));
        assert!(e.contains("args[\"a.b\"]: expected an integer"), "{e}");
        assert!(e.contains("args.ok-1: expected an integer"), "{e}");
    }

    // --- arrays ----------------------------------------------------------

    #[test]
    fn items_errors_carry_index_and_nested_path() {
        let schema = ObjectSchema::new()
            .object_array(
                "items",
                "i",
                ObjectSchema::new().string("name", "n", true),
                false,
            )
            .build();
        let e = err(
            &schema,
            &json!({"items": [{"name": "a"}, {"name": "b"}, {"name": 3}]}),
        );
        assert!(
            e.contains("args.items[2].name: expected a string; got integer 3"),
            "{e}"
        );
    }

    #[test]
    fn array_sizes_are_bounded() {
        let schema = json!({"type": "array", "minItems": 1, "maxItems": 2});
        validate(&schema, &json!([1])).unwrap();
        assert!(err(&schema, &json!([])).contains("at least 1 items; got 0"));
        assert!(err(&schema, &json!([1, 2, 3])).contains("at most 2 items; got 3"));
    }

    #[test]
    fn unique_items_uses_json_equality() {
        let schema = json!({"type": "array", "uniqueItems": true});
        validate(&schema, &json!([1, 2, "1", {"a": 1}, {"a": 2}])).unwrap();
        let e = err(&schema, &json!([1, 2, 1.0]));
        assert!(e.contains("args[2]: duplicates args[0]"), "{e}");
        assert!(validate(&schema, &json!([{"a": 1, "b": 2}, {"b": 2, "a": 1}])).is_err());
        validate(
            &json!({"type": "array", "uniqueItems": false}),
            &json!([1, 1]),
        )
        .unwrap();
    }

    // --- enum and const --------------------------------------------------

    #[test]
    fn enum_rejection_lists_allowed_values_and_suggests() {
        let schema = ObjectSchema::new()
            .string_enum("method", "m", &["GET", "POST", "PUT"], false)
            .build();
        let e = err(&schema, &json!({"method": "get"}));
        assert!(
            e.contains(
                "args.method: must be one of \"GET\", \"POST\", \"PUT\"; got string \"get\""
            ),
            "{e}"
        );
        assert!(e.contains("did you mean \"GET\"?"), "{e}");
        assert_eq!(
            problem_lines(&e).len(),
            1,
            "type error must not repeat the enum problem: {e}"
        );
        let e = err(&schema, &json!({"method": 5}));
        assert!(
            e.contains("must be one of") && e.contains("got integer 5"),
            "{e}"
        );
        validate(&schema, &json!({"method": "POST"})).unwrap();
    }

    #[test]
    fn long_enums_are_summarised() {
        let values: Vec<String> = (0..60).map(|i| format!("v{i}")).collect();
        let schema = json!({"enum": values});
        let e = err(&schema, &json!("nope"));
        assert!(e.contains("and 20 more"), "{e}");
    }

    #[test]
    fn enum_and_const_treat_equal_numbers_as_equal() {
        validate(&json!({"enum": [1, 2]}), &json!(1.0)).unwrap();
        validate(&json!({"const": 3}), &json!(3.0)).unwrap();
        validate(&json!({"const": {"a": [1, 2]}}), &json!({"a": [1.0, 2]})).unwrap();
        let e = err(&json!({"const": "x"}), &json!("y"));
        assert!(e.contains("must be exactly \"x\"; got string \"y\""), "{e}");
        validate(&json!({"enum": [null, "a"]}), &json!(null)).unwrap();
    }

    // --- numeric bounds --------------------------------------------------

    #[test]
    fn numeric_bounds_accept_and_reject() {
        let s = json!({"type": "integer", "minimum": 1, "maximum": 10});
        validate(&s, &json!(1)).unwrap();
        validate(&s, &json!(10)).unwrap();
        assert!(err(&s, &json!(0)).contains("must be at least 1; got 0"));
        assert!(err(&s, &json!(11)).contains("must be at most 10; got 11"));
        let x = json!({"exclusiveMinimum": 0, "exclusiveMaximum": 1});
        validate(&x, &json!(0.5)).unwrap();
        assert!(err(&x, &json!(0)).contains("must be greater than 0; got 0"));
        assert!(err(&x, &json!(1)).contains("must be less than 1; got 1"));
    }

    #[test]
    fn numeric_comparison_is_exact_beyond_f64_precision() {
        let s = json!({"maximum": 9_007_199_254_740_993_i64});
        validate(&s, &json!(9_007_199_254_740_993_i64)).unwrap();
        assert!(validate(&s, &json!(9_007_199_254_740_994_i64)).is_err());
        validate(&json!({"minimum": 0}), &json!(u64::MAX)).unwrap();
        assert!(validate(&json!({"minimum": 0}), &json!(i64::MIN)).is_err());
        validate(&json!({"maximum": 0.5}), &json!(0)).unwrap();
        assert!(validate(&json!({"minimum": 0.5}), &json!(0)).is_err());
        validate(&json!({"minimum": -0.0}), &json!(0)).unwrap();
        assert!(validate(&json!({"maximum": 1e19}), &json!(u64::MAX)).is_err());
    }

    #[test]
    fn keywords_for_other_types_are_ignored() {
        let schema = json!({"minimum": 5, "minLength": 2, "minItems": 3, "required": ["a"]});
        validate(&schema, &json!("abc")).unwrap();
        validate(&schema, &json!(7)).unwrap();
        validate(&schema, &json!(null)).unwrap();
        assert!(validate(&schema, &json!(1)).is_err());
    }

    // --- strings ---------------------------------------------------------

    #[test]
    fn string_length_counts_unicode_scalar_values() {
        let s = json!({"type": "string", "maxLength": 3});
        validate(&s, &json!("😀😀😀")).unwrap();
        let e = err(&s, &json!("😀😀😀😀"));
        assert!(e.contains("at most 3 characters long; got 4"), "{e}");
        let min = json!({"minLength": 3});
        validate(&min, &json!("e\u{301}x")).unwrap();
        assert!(err(&min, &json!("é")).contains("at least 3 characters long; got 1"));
    }

    // --- reporting -------------------------------------------------------

    #[test]
    fn several_problems_are_reported_together_in_a_stable_order() {
        let schema = ObjectSchema::new()
            .string("path", "p", true)
            .integer("count", "c", false)
            .string_enum("mode", "m", &["a", "b"], false)
            .build();
        let e = err(&schema, &json!({"count": "x", "mode": "zzz", "extra": 1}));
        assert!(e.starts_with("4 problems with the arguments:\n"), "{e}");
        let lines = problem_lines(&e);
        assert_eq!(lines.len(), 4);
        assert!(lines[0].contains("args.path: required property is missing"));
        assert!(lines[1].contains("args.count"));
        assert!(lines[2].contains("args.mode"));
        assert!(lines[3].contains("args.extra: unknown property"));
    }

    #[test]
    fn problem_count_is_capped_at_eight() {
        let schema = json!({"type": "array", "items": {"type": "string"}});
        let instance = Value::Array((0..20).map(Value::from).collect());
        let e = err(&schema, &instance);
        assert!(
            e.starts_with("8 or more problems with the arguments (showing the first 8):"),
            "{e}"
        );
        assert_eq!(problem_lines(&e).len(), 8);
        assert!(e.contains("args[7]") && !e.contains("args[8]"));
        let exactly = Value::Array((0..8).map(Value::from).collect());
        let e = err(&schema, &exactly);
        assert!(e.starts_with("8 problems with the arguments:"), "{e}");
    }

    #[test]
    fn echoed_values_are_truncated() {
        let schema = json!({"type": "integer"});
        let e = err(&schema, &json!("x".repeat(10_000)));
        assert!(e.len() < 250, "{}", e.len());
        assert!(e.contains('…'));
        let big = Value::Array((0..100_000).map(Value::from).collect());
        let e = err(&schema, &big);
        assert!(e.len() < 250 && e.contains('…'), "{}", e.len());
        let e = err(&json!({"enum": ["a"]}), &json!("é".repeat(500)));
        assert!(e.chars().count() < 250, "{e}");
    }

    #[test]
    fn echo_never_splits_a_character_and_escapes_controls() {
        assert_eq!(echo(&json!("a\nb")), "\"a\\nb\"");
        let long = echo(&json!("😀".repeat(200)));
        assert_eq!(long.chars().count(), 81);
        assert!(long.ends_with('…'));
        assert_eq!(echo(&json!([1, 2])), "[1,2]");
    }

    #[test]
    fn validate_as_uses_custom_root_and_subject() {
        let e = validate_as(
            "result",
            "the structured result",
            &json!({"type": "object"}),
            &json!(1),
        )
        .unwrap_err();
        assert_eq!(
            e,
            "1 problem with the structured result:\n- result: expected an object; got integer 1"
        );
    }

    // --- depth -----------------------------------------------------------

    #[test]
    fn instance_depth_is_bounded() {
        validate(&json!(true), &nested_arrays(64)).unwrap();
        let e = err(&json!(true), &nested_arrays(65));
        assert!(e.contains("64 levels"), "{e}");
        let deep = nested_arrays(200);
        assert!(validate(&json!({"type": "array"}), &deep).is_err());
    }

    #[test]
    fn deeply_nested_schema_checks_are_bounded() {
        let mut s = json!({"type": "string"});
        for _ in 0..40 {
            s = json!({"properties": {"a": s}});
        }
        let e = check_supported(&s).unwrap_err();
        assert!(e.contains("64 levels"), "{e}");
    }

    // --- schema forms ----------------------------------------------------

    #[test]
    fn annotation_keywords_are_accepted_and_ignored() {
        let schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "string",
            "title": "t",
            "description": "d",
            "default": 3,
            "examples": [1],
            "deprecated": true,
            "readOnly": true,
            "writeOnly": false,
            "format": "uri",
            "x-mcp-header": "X-Thing",
        });
        validate(&schema, &json!("not a uri")).unwrap();
        check_supported(&schema).unwrap();
    }

    #[test]
    fn boolean_schemas_work_as_subschemas() {
        validate(&json!(true), &json!(1)).unwrap();
        assert!(err(&json!(false), &json!(1)).contains("no value is allowed here"));
        let schema = json!({"properties": {"a": false}, "additionalProperties": false});
        assert!(validate(&schema, &json!({"a": 1})).is_err());
        validate(&schema, &json!({})).unwrap();
        check_supported(&schema).unwrap();
    }

    #[test]
    fn malformed_schemas_fail_closed_without_panicking() {
        let cases = [
            (json!({"type": "strng"}), json!("xyz")),
            (json!({"type": []}), json!("xyz")),
            (json!({"minLength": "3"}), json!("xyz")),
            (json!({"required": "a"}), json!({"a": 1})),
            (json!({"properties": 3}), json!({"a": 1})),
            (json!({"enum": 3}), json!("xyz")),
            (json!({"minimum": true}), json!(4)),
            (json!({"minItems": -1}), json!([])),
            (json!({"uniqueItems": 1}), json!([1])),
            (json!(7), json!("xyz")),
        ];
        for (bad, inst) in cases {
            let e = validate(&bad, &inst).expect_err(&format!("{bad} should fail"));
            assert!(e.contains("malformed"), "{bad}: {e}");
            assert!(check_supported(&bad).is_err(), "{bad}");
        }
    }

    // --- check_supported -------------------------------------------------

    #[test]
    fn check_supported_accepts_every_implemented_keyword() {
        let schema = json!({
            "type": "object",
            "properties": {
                "s": {"type": "string", "minLength": 1, "maxLength": 9, "enum": ["a"], "const": "a"},
                "n": {"type": "number", "minimum": 0, "maximum": 5, "exclusiveMinimum": -1, "exclusiveMaximum": 6},
                "a": {"type": "array", "items": {"type": "string"}, "minItems": 0, "maxItems": 3, "uniqueItems": true},
            },
            "required": ["s"],
            "additionalProperties": {"type": "string"},
            "minProperties": 1,
            "maxProperties": 5,
        });
        check_supported(&schema).unwrap();
    }

    #[test]
    fn check_supported_names_the_unsupported_keyword_and_location() {
        for keyword in [
            "oneOf",
            "anyOf",
            "allOf",
            "not",
            "pattern",
            "$ref",
            "$defs",
            "if",
            "patternProperties",
            "multipleOf",
            "x-custom",
        ] {
            let schema = json!({"type": "object", "properties": {"p": {keyword: 1}}});
            let e = check_supported(&schema).unwrap_err();
            assert!(
                e.contains(&format!("\"{keyword}\"")) && e.contains("#/properties/p"),
                "{keyword}: {e}"
            );
        }
        let nested = json!({"type": "array", "items": {"pattern": "x"}});
        assert!(check_supported(&nested).unwrap_err().contains("#/items"));
    }

    #[test]
    fn a_property_named_like_a_keyword_is_not_a_keyword() {
        let schema = json!({"properties": {"pattern": {"type": "string"}, "oneOf": {"type": "string"}, "$ref": {"type": "string"}}});
        check_supported(&schema).unwrap();
        validate(&schema, &json!({"pattern": "x"})).unwrap();
    }

    #[test]
    fn check_supported_rejects_malformed_keyword_values() {
        for bad in [
            json!({"type": "strng"}),
            json!({"type": ["string", "string"]}),
            json!({"type": []}),
            json!({"items": [{"type": "string"}]}),
            json!({"items": "string"}),
            json!({"required": "a"}),
            json!({"required": ["a", "a"]}),
            json!({"properties": []}),
            json!({"additionalProperties": "no"}),
            json!({"minimum": "1"}),
            json!({"exclusiveMinimum": true}),
            json!({"minLength": -1}),
            json!({"maxItems": 1.5}),
            json!({"uniqueItems": "yes"}),
            json!({"enum": "a"}),
            json!(3),
        ] {
            assert!(check_supported(&bad).is_err(), "{bad}");
        }
        check_supported(&json!({"minLength": 2.0})).unwrap();
    }

    // --- check_input_schema ----------------------------------------------

    fn described(schema: Value) -> Value {
        json!({"type": "object", "properties": {"p": schema}, "required": [], "additionalProperties": false})
    }

    #[test]
    fn input_schema_root_must_be_an_object_type() {
        for bad in [
            json!({}),
            json!({"type": "array"}),
            json!({"type": ["object", "null"]}),
            json!(true),
        ] {
            let e = check_input_schema(&bad).unwrap_err();
            assert!(e.contains("\"type\": \"object\""), "{bad}: {e}");
        }
        check_input_schema(&json!({"type": "object", "properties": {}, "required": []})).unwrap();
    }

    #[test]
    fn input_schema_required_names_must_be_declared() {
        let bad = json!({"type": "object", "properties": {"a": {"type": "string", "description": "d"}}, "required": ["b"]});
        let e = check_input_schema(&bad).unwrap_err();
        assert!(e.contains("required property \"b\" is not declared"), "{e}");
        let none = json!({"type": "object", "required": ["a"]});
        assert!(check_input_schema(&none).is_err());
        let nested = described(
            json!({"type": "object", "description": "d", "properties": {}, "required": ["x"]}),
        );
        assert!(check_input_schema(&nested)
            .unwrap_err()
            .contains("#/properties/p"));
    }

    #[test]
    fn input_schema_properties_need_non_empty_descriptions() {
        for bad in [
            json!({"type": "string"}),
            json!({"type": "string", "description": ""}),
            json!({"type": "string", "description": "   "}),
            json!({"type": "string", "description": 5}),
            json!(true),
        ] {
            let e = check_input_schema(&described(bad.clone())).unwrap_err();
            assert!(
                e.contains("\"p\"") && e.contains("description"),
                "{bad}: {e}"
            );
        }
        let inner = described(
            json!({"type": "object", "description": "d", "properties": {"q": {"type": "string"}}}),
        );
        assert!(check_input_schema(&inner)
            .unwrap_err()
            .contains("#/properties/p/properties/q"));
        let in_items = described(
            json!({"type": "array", "description": "d", "items": {"type": "object", "properties": {"q": {"type": "string"}}}}),
        );
        assert!(check_input_schema(&in_items).is_err());
    }

    #[test]
    fn input_schema_enums_must_be_non_empty_and_unique() {
        let empty = described(json!({"type": "string", "description": "d", "enum": []}));
        assert!(check_input_schema(&empty)
            .unwrap_err()
            .contains("must not be empty"));
        let dup = described(json!({"type": "string", "description": "d", "enum": ["a", "b", "a"]}));
        assert!(check_input_schema(&dup)
            .unwrap_err()
            .contains("more than once"));
        let num_dup = described(json!({"type": "number", "description": "d", "enum": [1, 1.0]}));
        assert!(check_input_schema(&num_dup).is_err());
        let ok = described(json!({"type": "string", "description": "d", "enum": ["a", "b"]}));
        check_input_schema(&ok).unwrap();
    }

    #[test]
    fn input_schema_runs_the_supported_keyword_check_too() {
        let bad = described(json!({"type": "string", "description": "d", "pattern": "x"}));
        assert!(check_input_schema(&bad)
            .unwrap_err()
            .contains("\"pattern\""));
    }

    #[test]
    fn x_mcp_header_accepts_scalar_properties_with_token_names() {
        let schema = json!({"type": "object", "properties": {
            "region": {"type": "string", "description": "d", "x-mcp-header": "Region"},
            "tries": {"type": "integer", "description": "d", "x-mcp-header": "X-Tries"},
            "dry": {"type": "boolean", "description": "d", "x-mcp-header": "Dry.Run_1"},
            "opts": {"type": "object", "description": "d", "properties": {
                "zone": {"type": "string", "description": "d", "x-mcp-header": "Zone"}
            }},
        }});
        check_input_schema(&schema).unwrap();
    }

    #[test]
    fn x_mcp_header_rejects_bad_names_types_and_locations() {
        let header = |extra: Value| described(extra);
        for name in [
            json!(""),
            json!("Bad Name"),
            json!("a:b"),
            json!("héader"),
            json!(3),
            json!("a/b"),
        ] {
            let s = header(json!({"type": "string", "description": "d", "x-mcp-header": name}));
            assert!(
                check_input_schema(&s)
                    .unwrap_err()
                    .contains("HTTP header token"),
                "{name}"
            );
        }
        for ty in [
            json!("array"),
            json!("object"),
            json!("number"),
            json!(["string", "null"]),
        ] {
            let s = header(json!({"type": ty, "description": "d", "x-mcp-header": "H"}));
            let e = check_input_schema(&s).unwrap_err();
            assert!(e.contains("string, integer or boolean"), "{e}");
        }
        let in_items = header(
            json!({"type": "array", "description": "d", "items": {"type": "string", "x-mcp-header": "H"}}),
        );
        assert!(check_input_schema(&in_items)
            .unwrap_err()
            .contains("reachable through \"properties\" alone"));
        let in_additional = header(
            json!({"type": "object", "description": "d", "additionalProperties": {"type": "string", "x-mcp-header": "H"}}),
        );
        assert!(check_input_schema(&in_additional).is_err());
    }

    #[test]
    fn x_mcp_header_names_are_unique_ignoring_case() {
        let schema = json!({"type": "object", "properties": {
            "a": {"type": "string", "description": "d", "x-mcp-header": "Region"},
            "b": {"type": "string", "description": "d", "x-mcp-header": "REGION"},
        }});
        let e = check_input_schema(&schema).unwrap_err();
        assert!(
            e.contains("duplicates") && e.contains("case-insensitive"),
            "{e}"
        );
    }

    // --- helpers ---------------------------------------------------------

    #[test]
    fn edit_distance_is_levenshtein_and_bounded() {
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("same", "same"), 0);
        assert_eq!(edit_distance(&"a".repeat(100), "a"), usize::MAX);
    }

    #[test]
    fn canonical_form_unifies_equal_values_only() {
        let c = |v: Value| {
            let mut s = String::new();
            canon(&v, &mut s);
            s
        };
        assert_eq!(c(json!(1)), c(json!(1.0)));
        assert_eq!(c(json!(0)), c(parse("-0.0")));
        assert_eq!(c(json!({"a": 1, "b": 2})), c(json!({"b": 2, "a": 1})));
        assert_ne!(c(json!(1)), c(json!("1")));
        assert_ne!(c(json!([1, 2])), c(json!([2, 1])));
        assert_ne!(c(json!(0.1)), c(json!(0.2)));
    }
}
