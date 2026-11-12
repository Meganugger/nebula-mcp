//! Tool argument schemas.
//!
//! A tool declares its arguments once, as an [`ObjectSchema`]. The same value
//! produces the JSON Schema advertised to clients and validates every call
//! before the tool runs, so what is advertised and what is enforced cannot
//! drift apart. Validation errors are written for a model to act on: they
//! name the argument, say what was expected, and suggest the intended name
//! for a near miss.

use serde_json::{json, Map, Value};

use crate::error::ToolError;

/// The type of one argument.
#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    /// A string, optionally restricted to a fixed set of values.
    String {
        /// Allowed values, if restricted.
        one_of: Option<Vec<String>>,
    },
    /// An integer within a range.
    Integer {
        /// Smallest allowed value.
        min: i64,
        /// Largest allowed value.
        max: i64,
    },
    /// Any JSON number.
    Number,
    /// A boolean.
    Boolean,
    /// An array of strings.
    StringArray,
    /// An object whose values are all strings.
    StringMap,
    /// An array of objects with the given shape.
    ObjectArray(ObjectSchema),
    /// Any JSON value.
    Json,
}

/// One declared argument.
#[derive(Debug, Clone, PartialEq)]
pub struct Property {
    /// Argument name.
    pub name: String,
    /// What the argument means, written for the model.
    pub description: String,
    /// Whether the argument must be present.
    pub required: bool,
    /// Value used when the argument is absent (advertised to clients).
    pub default: Option<Value>,
    /// The argument's type.
    pub kind: Kind,
}

/// The shape of a tool's arguments (or of an object inside them).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ObjectSchema {
    properties: Vec<Property>,
}

impl ObjectSchema {
    /// Start an empty schema. Undeclared arguments are always rejected.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn push(mut self, name: &str, description: &str, required: bool, default: Option<Value>, kind: Kind) -> Self {
        assert!(
            !self.properties.iter().any(|p| p.name == name),
            "argument '{name}' is declared twice"
        );
        self.properties.push(Property {
            name: name.to_string(),
            description: description.to_string(),
            required,
            default,
            kind,
        });
        self
    }

    /// A string argument.
    #[must_use]
    pub fn string(self, name: &str, description: &str, required: bool) -> Self {
        self.push(name, description, required, None, Kind::String { one_of: None })
    }

    /// A string argument restricted to `values`.
    #[must_use]
    pub fn enumerated(self, name: &str, description: &str, values: &[&str], required: bool) -> Self {
        let one_of = Some(values.iter().map(|v| (*v).to_string()).collect());
        self.push(name, description, required, None, Kind::String { one_of })
    }

    /// An optional string argument restricted to `values`, with a default.
    #[must_use]
    pub fn enumerated_or(self, name: &str, description: &str, values: &[&str], default: &str) -> Self {
        assert!(values.contains(&default), "default '{default}' is not one of the values");
        let one_of = Some(values.iter().map(|v| (*v).to_string()).collect());
        self.push(name, description, false, Some(json!(default)), Kind::String { one_of })
    }

    /// A non-negative integer argument.
    #[must_use]
    pub fn integer(self, name: &str, description: &str, required: bool) -> Self {
        self.integer_in(name, description, required, 0, i64::MAX)
    }

    /// An integer argument within `min..=max`.
    #[must_use]
    pub fn integer_in(self, name: &str, description: &str, required: bool, min: i64, max: i64) -> Self {
        self.push(name, description, required, None, Kind::Integer { min, max })
    }

    /// A number argument.
    #[must_use]
    pub fn number(self, name: &str, description: &str, required: bool) -> Self {
        self.push(name, description, required, None, Kind::Number)
    }

    /// An optional boolean argument with a default.
    #[must_use]
    pub fn boolean(self, name: &str, description: &str, default: bool) -> Self {
        self.push(name, description, false, Some(json!(default)), Kind::Boolean)
    }

    /// An array-of-strings argument.
    #[must_use]
    pub fn string_array(self, name: &str, description: &str, required: bool) -> Self {
        self.push(name, description, required, None, Kind::StringArray)
    }

    /// An optional object argument whose values are strings.
    #[must_use]
    pub fn string_map(self, name: &str, description: &str) -> Self {
        self.push(name, description, false, None, Kind::StringMap)
    }

    /// An array of objects, each with the shape `item`.
    #[must_use]
    pub fn object_array(self, name: &str, description: &str, required: bool, item: ObjectSchema) -> Self {
        self.push(name, description, required, None, Kind::ObjectArray(item))
    }

    /// An argument that accepts any JSON value.
    #[must_use]
    pub fn json(self, name: &str, description: &str, required: bool) -> Self {
        self.push(name, description, required, None, Kind::Json)
    }

    /// The declared arguments, in declaration order.
    #[must_use]
    pub fn properties(&self) -> &[Property] {
        &self.properties
    }

    /// Look up a declared argument.
    #[must_use]
    pub fn property(&self, name: &str) -> Option<&Property> {
        self.properties.iter().find(|p| p.name == name)
    }

    /// The JSON Schema (2020-12) advertised to clients.
    #[must_use]
    pub fn to_json_schema(&self) -> Value {
        let mut properties = Map::new();
        let mut required = Vec::new();
        for p in &self.properties {
            let mut schema = match &p.kind {
                Kind::String { one_of: None } => json!({"type": "string"}),
                Kind::String { one_of: Some(values) } => json!({"type": "string", "enum": values}),
                Kind::Integer { min, max } => {
                    let mut s = json!({"type": "integer", "minimum": min});
                    if *max != i64::MAX {
                        s["maximum"] = json!(max);
                    }
                    s
                }
                Kind::Number => json!({"type": "number"}),
                Kind::Boolean => json!({"type": "boolean"}),
                Kind::StringArray => json!({"type": "array", "items": {"type": "string"}}),
                Kind::StringMap => {
                    json!({"type": "object", "additionalProperties": {"type": "string"}})
                }
                Kind::ObjectArray(item) => json!({"type": "array", "items": item.to_json_schema()}),
                Kind::Json => json!({}),
            };
            schema["description"] = json!(p.description);
            if let Some(default) = &p.default {
                schema["default"] = default.clone();
            }
            properties.insert(p.name.clone(), schema);
            if p.required {
                required.push(json!(p.name));
            }
        }
        json!({
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false,
        })
    }

    /// Validate an arguments value against this schema and return it as
    /// [`Args`]. `null` (or an absent value) is an empty object, and a `null`
    /// argument is treated as absent.
    pub fn validate(&self, value: Value) -> Result<Args, ToolError> {
        let mut object = match value {
            Value::Object(map) => map,
            Value::Null => Map::new(),
            other => {
                return Err(ToolError::InvalidArguments(format!(
                    "arguments must be a JSON object, not {}",
                    type_name(&other)
                )))
            }
        };
        object.retain(|_, v| !v.is_null());
        let mut problems = Vec::new();
        self.check(&mut object, "", &mut problems);
        if problems.is_empty() {
            Ok(Args { values: object })
        } else {
            Err(ToolError::InvalidArguments(problems.join("; ")))
        }
    }

    fn check(&self, object: &mut Map<String, Value>, prefix: &str, problems: &mut Vec<String>) {
        for key in object.keys() {
            if self.property(key).is_none() {
                let hint = self
                    .closest(key)
                    .map(|n| format!(" (did you mean '{n}'?)"))
                    .unwrap_or_default();
                problems.push(format!("unknown argument '{prefix}{key}'{hint}"));
            }
        }
        for p in &self.properties {
            let name = format!("{prefix}{}", p.name);
            let Some(value) = object.get_mut(&p.name) else {
                if p.required {
                    problems.push(format!("missing required argument '{name}'"));
                }
                continue;
            };
            match &p.kind {
                Kind::String { one_of } => match value.as_str() {
                    None => problems.push(expected(&name, "a string", value)),
                    Some(s) => {
                        if let Some(values) = one_of {
                            if !values.iter().any(|v| v == s) {
                                problems.push(format!(
                                    "'{name}' must be one of {}, not \"{s}\"",
                                    values
                                        .iter()
                                        .map(|v| format!("\"{v}\""))
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                ));
                            }
                        }
                    }
                },
                Kind::Integer { min, max } => match as_integer(value) {
                    None => problems.push(expected(&name, "an integer", value)),
                    Some(n) if n < *min || n > *max => {
                        if *max == i64::MAX {
                            problems.push(format!("'{name}' must be at least {min}, not {n}"));
                        } else {
                            problems.push(format!(
                                "'{name}' must be between {min} and {max}, not {n}"
                            ));
                        }
                    }
                    Some(n) => *value = json!(n),
                },
                Kind::Number => {
                    if !value.is_number() {
                        problems.push(expected(&name, "a number", value));
                    }
                }
                Kind::Boolean => {
                    if !value.is_boolean() {
                        problems.push(expected(&name, "true or false", value));
                    }
                }
                Kind::StringArray => match value.as_array() {
                    Some(items) if items.iter().all(Value::is_string) => {}
                    _ => problems.push(expected(&name, "an array of strings", value)),
                },
                Kind::StringMap => match value.as_object() {
                    Some(map) if map.values().all(Value::is_string) => {}
                    _ => problems.push(expected(&name, "an object with string values", value)),
                },
                Kind::ObjectArray(item) => match value.as_array_mut() {
                    None => problems.push(expected(&name, "an array of objects", value)),
                    Some(items) => {
                        for (i, entry) in items.iter_mut().enumerate() {
                            match entry.as_object_mut() {
                                Some(map) => {
                                    map.retain(|_, v| !v.is_null());
                                    item.check(map, &format!("{name}[{i}]."), problems);
                                }
                                None => problems.push(format!("'{name}[{i}]' must be an object")),
                            }
                        }
                    }
                },
                Kind::Json => {}
            }
        }
    }

    /// The declared name a misspelt argument most likely meant.
    fn closest(&self, key: &str) -> Option<&str> {
        let squash = |s: &str| -> String {
            s.chars()
                .filter(|c| c.is_alphanumeric())
                .flat_map(char::to_lowercase)
                .collect()
        };
        let wanted = squash(key);
        self.properties
            .iter()
            .map(|p| (edit_distance(&wanted, &squash(&p.name)), p.name.as_str()))
            .filter(|(d, _)| *d <= 2)
            .min_by_key(|(d, _)| *d)
            .map(|(_, n)| n)
    }
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

fn expected(name: &str, what: &str, got: &Value) -> String {
    format!("'{name}' must be {what}, not {}", type_name(got))
}

/// Integers, including whole-valued floats such as `5.0`, which models
/// sometimes send.
fn as_integer(value: &Value) -> Option<i64> {
    if let Some(n) = value.as_i64() {
        return Some(n);
    }
    let f = value.as_f64()?;
    (f.fract() == 0.0 && f.abs() < 9.0e15).then_some(f as i64)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut previous = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let substitution = previous + usize::from(ca != cb);
            previous = row[j + 1];
            row[j + 1] = substitution.min(row[j] + 1).min(previous + 1);
        }
    }
    row[b.len()]
}

/// A tool's arguments after validation.
#[derive(Debug, Clone, Default)]
pub struct Args {
    values: Map<String, Value>,
}

impl Args {
    fn get(&self, key: &str) -> Option<&Value> {
        self.values.get(key)
    }

    fn missing(key: &str) -> ToolError {
        ToolError::InvalidArguments(format!("missing required argument '{key}'"))
    }

    /// Whether the argument was supplied.
    #[must_use]
    pub fn has(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    /// Required string.
    pub fn str(&self, key: &str) -> Result<&str, ToolError> {
        self.opt_str(key).ok_or_else(|| Self::missing(key))
    }

    /// Optional string.
    #[must_use]
    pub fn opt_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Value::as_str)
    }

    /// Optional string with a default.
    #[must_use]
    pub fn str_or<'a>(&'a self, key: &str, default: &'a str) -> &'a str {
        self.opt_str(key).unwrap_or(default)
    }

    /// Optional boolean with a default.
    #[must_use]
    pub fn bool_or(&self, key: &str, default: bool) -> bool {
        self.get(key).and_then(Value::as_bool).unwrap_or(default)
    }

    /// Optional non-negative integer.
    #[must_use]
    pub fn opt_u64(&self, key: &str) -> Option<u64> {
        self.get(key).and_then(Value::as_u64)
    }

    /// Optional non-negative integer with a default.
    #[must_use]
    pub fn u64_or(&self, key: &str, default: u64) -> u64 {
        self.opt_u64(key).unwrap_or(default)
    }

    /// Required non-negative integer.
    pub fn u64(&self, key: &str) -> Result<u64, ToolError> {
        self.opt_u64(key).ok_or_else(|| Self::missing(key))
    }

    /// Optional signed integer.
    #[must_use]
    pub fn opt_i64(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(Value::as_i64)
    }

    /// Optional number.
    #[must_use]
    pub fn opt_f64(&self, key: &str) -> Option<f64> {
        self.get(key).and_then(Value::as_f64)
    }

    /// Array of strings (empty if absent).
    #[must_use]
    pub fn str_array(&self, key: &str) -> Vec<String> {
        self.get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// String-to-string map (empty if absent).
    #[must_use]
    pub fn string_map(&self, key: &str) -> Vec<(String, String)> {
        self.get(key)
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Array of objects, each as its own [`Args`] (empty if absent).
    #[must_use]
    pub fn objects(&self, key: &str) -> Vec<Args> {
        self.get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_object())
                    .map(|map| Args {
                        values: map.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Raw value of an argument.
    #[must_use]
    pub fn value(&self, key: &str) -> Option<&Value> {
        self.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> ObjectSchema {
        ObjectSchema::new()
            .string("path", "File path.", true)
            .boolean("clearEnv", "Start clean.", false)
            .integer("timeoutSecs", "Timeout.", false)
            .integer_in("port", "Port.", false, 1, 65535)
            .enumerated("mode", "Mode.", &["read", "write"], false)
            .string_array("args", "Arguments.", false)
            .string_map("env", "Environment.")
            .object_array(
                "edits",
                "Edits.",
                false,
                ObjectSchema::new()
                    .string("old", "Old text.", true)
                    .string("new", "New text.", true),
            )
            .json("body", "Any JSON.", false)
    }

    fn err(value: Value) -> String {
        schema().validate(value).unwrap_err().to_string()
    }

    #[test]
    fn valid_arguments_are_accepted_and_typed() {
        let a = schema()
            .validate(json!({
                "path": "a.txt", "clearEnv": true, "timeoutSecs": 5.0, "port": 443,
                "mode": "read", "args": ["x", "y"], "env": {"A": "1"},
                "edits": [{"old": "a", "new": "b"}], "body": [1, {"k": null}], "unused": null
            }))
            .unwrap();
        assert_eq!(a.str("path").unwrap(), "a.txt");
        assert!(a.bool_or("clearEnv", false));
        assert_eq!(a.opt_u64("timeoutSecs"), Some(5));
        assert_eq!(a.str_array("args"), vec!["x", "y"]);
        assert_eq!(a.string_map("env"), vec![("A".to_string(), "1".to_string())]);
        assert_eq!(a.objects("edits")[0].str("new").unwrap(), "b");
        assert!(!a.has("unused"));
        assert!(a.value("body").is_some());
    }

    #[test]
    fn null_or_missing_arguments_are_an_empty_object() {
        let s = ObjectSchema::new().string("x", "X.", false);
        assert!(s.validate(Value::Null).is_ok());
        assert!(s.validate(json!({})).is_ok());
        assert!(s.validate(json!([])).is_err());
        assert!(s.validate(json!("text")).is_err());
    }

    #[test]
    fn unknown_arguments_are_rejected_with_a_suggestion() {
        let msg = err(json!({"path": "a", "clear_env": true}));
        assert!(msg.contains("unknown argument 'clear_env'") && msg.contains("'clearEnv'"), "{msg}");
        let msg = err(json!({"path": "a", "timeoutSec": 3}));
        assert!(msg.contains("'timeoutSecs'"), "{msg}");
        let msg = err(json!({"path": "a", "wholly_unrelated": 1}));
        assert!(msg.contains("unknown argument") && !msg.contains("did you mean"), "{msg}");
    }

    #[test]
    fn missing_wrong_type_range_and_enum_are_all_reported() {
        let msg = err(json!({"clearEnv": "yes", "port": 70000, "mode": "delete", "timeoutSecs": -1, "args": [1]}));
        for needle in [
            "missing required argument 'path'",
            "'clearEnv' must be true or false, not a string",
            "'port' must be between 1 and 65535, not 70000",
            "'mode' must be one of \"read\", \"write\", not \"delete\"",
            "'timeoutSecs' must be at least 0, not -1",
            "'args' must be an array of strings",
        ] {
            assert!(msg.contains(needle), "missing: {needle}\n in: {msg}");
        }
        assert!(err(json!({"path": "a", "timeoutSecs": 1.5})).contains("an integer"));
        assert!(err(json!({"path": "a", "timeoutSecs": "5"})).contains("not a string"));
    }

    #[test]
    fn nested_objects_are_validated() {
        let msg = err(json!({"path": "a", "edits": [{"old": "x"}, {"old": "x", "new": "y", "nwe": 1}]}));
        assert!(msg.contains("missing required argument 'edits[0].new'"), "{msg}");
        assert!(msg.contains("unknown argument 'edits[1].nwe'"), "{msg}");
    }

    #[test]
    fn json_schema_matches_the_declaration() {
        let s = schema().to_json_schema();
        assert_eq!(s["type"], "object");
        assert_eq!(s["additionalProperties"], false);
        assert_eq!(s["required"], json!(["path"]));
        assert_eq!(s["properties"]["mode"]["enum"], json!(["read", "write"]));
        assert_eq!(s["properties"]["port"]["maximum"], 65535);
        assert_eq!(s["properties"]["clearEnv"]["default"], false);
        assert_eq!(s["properties"]["edits"]["items"]["required"], json!(["old", "new"]));
        assert!(s["properties"]["timeoutSecs"].get("maximum").is_none());
    }

    #[test]
    #[should_panic(expected = "declared twice")]
    fn duplicate_declarations_panic() {
        let _ = ObjectSchema::new().string("a", "A.", true).string("a", "A.", true);
    }
}
