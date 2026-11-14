//! Typed argument extraction from a tool's JSON arguments object.
//!
//! The dispatcher validates arguments against the tool's schema before the
//! tool runs, so these accessors are a second line of defence: they never
//! panic and answer a wrong type with a [`ToolError::InvalidArguments`] that
//! names the field and what arrived. A `null` value counts as absent.

use serde_json::Value;

use crate::error::ToolError;
use crate::schema::{describe_value, integer_value};

/// A borrowed view over a tool's arguments object.
#[derive(Debug, Clone, Copy)]
pub struct Args<'a> {
    value: &'a Value,
}

fn invalid(msg: String) -> ToolError {
    ToolError::InvalidArguments(msg)
}

fn wrong_type(key: &str, want: &str, got: &Value) -> ToolError {
    invalid(format!(
        "field '{key}' must be {want}; got {}",
        describe_value(got)
    ))
}

impl<'a> Args<'a> {
    /// Wrap a JSON value, requiring an object (`null` is an empty object).
    pub fn new(value: &'a Value) -> Result<Self, ToolError> {
        if value.is_object() || value.is_null() {
            Ok(Self { value })
        } else {
            Err(invalid(format!(
                "arguments must be a JSON object; got {}",
                describe_value(value)
            )))
        }
    }

    fn get(&self, key: &str) -> Option<&'a Value> {
        self.value.get(key).filter(|v| !v.is_null())
    }

    fn missing(key: &str, what: &str) -> ToolError {
        invalid(format!("missing required {what} '{key}'"))
    }

    /// Raw access to an optional sub-value (`null` counts as absent).
    #[must_use]
    pub fn opt_value(&self, key: &str) -> Option<&'a Value> {
        self.get(key)
    }

    /// Required string field.
    pub fn str(&self, key: &str) -> Result<&'a str, ToolError> {
        match self.get(key) {
            None => Err(Self::missing(key, "string")),
            Some(v) => v.as_str().ok_or_else(|| wrong_type(key, "a string", v)),
        }
    }

    /// Optional string field.
    pub fn opt_str(&self, key: &str) -> Result<Option<&'a str>, ToolError> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => v
                .as_str()
                .map(Some)
                .ok_or_else(|| wrong_type(key, "a string", v)),
        }
    }

    /// Optional string with a default.
    pub fn str_or<'b>(&self, key: &str, default: &'b str) -> Result<&'b str, ToolError>
    where
        'a: 'b,
    {
        Ok(self.opt_str(key)?.unwrap_or(default))
    }

    /// Optional string restricted to `allowed`.
    pub fn opt_enum(&self, key: &str, allowed: &[&str]) -> Result<Option<&'a str>, ToolError> {
        let Some(s) = self.opt_str(key)? else {
            return Ok(None);
        };
        if allowed.contains(&s) {
            Ok(Some(s))
        } else {
            let list: Vec<String> = allowed.iter().map(|a| format!("\"{a}\"")).collect();
            Err(invalid(format!(
                "field '{key}' must be one of {}; got {}",
                list.join(", "),
                describe_value(&Value::String(s.to_string()))
            )))
        }
    }

    /// Required boolean field.
    pub fn bool(&self, key: &str) -> Result<bool, ToolError> {
        match self.get(key) {
            None => Err(Self::missing(key, "boolean")),
            Some(v) => v.as_bool().ok_or_else(|| wrong_type(key, "a boolean", v)),
        }
    }

    /// Optional boolean with a default.
    pub fn bool_or(&self, key: &str, default: bool) -> Result<bool, ToolError> {
        match self.get(key) {
            None => Ok(default),
            Some(v) => v.as_bool().ok_or_else(|| wrong_type(key, "a boolean", v)),
        }
    }

    /// Optional unsigned integer. Integral floats such as `30.0` are accepted,
    /// as the schema validator accepts them.
    pub fn opt_u64(&self, key: &str) -> Result<Option<u64>, ToolError> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => integer_value(v)
                .and_then(|i| u64::try_from(i).ok())
                .map(Some)
                .ok_or_else(|| wrong_type(key, "a non-negative integer", v)),
        }
    }

    /// Required unsigned integer.
    pub fn u64(&self, key: &str) -> Result<u64, ToolError> {
        self.opt_u64(key)?
            .ok_or_else(|| Self::missing(key, "non-negative integer"))
    }

    /// Optional unsigned integer with a default.
    pub fn u64_or(&self, key: &str, default: u64) -> Result<u64, ToolError> {
        Ok(self.opt_u64(key)?.unwrap_or(default))
    }

    /// Optional size or count with a default, bounded by the platform's
    /// `usize`.
    pub fn usize_or(&self, key: &str, default: usize) -> Result<usize, ToolError> {
        match self.opt_u64(key)? {
            None => Ok(default),
            Some(n) => usize::try_from(n).map_err(|_| {
                invalid(format!(
                    "field '{key}' is too large on this platform; got {n}"
                ))
            }),
        }
    }

    /// Optional signed integer.
    pub fn opt_i64(&self, key: &str) -> Result<Option<i64>, ToolError> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => integer_value(v)
                .and_then(|i| i64::try_from(i).ok())
                .map(Some)
                .ok_or_else(|| wrong_type(key, "an integer", v)),
        }
    }

    /// Required signed integer.
    pub fn i64(&self, key: &str) -> Result<i64, ToolError> {
        self.opt_i64(key)?
            .ok_or_else(|| Self::missing(key, "integer"))
    }

    /// Optional number (integer or fractional).
    pub fn opt_f64(&self, key: &str) -> Result<Option<f64>, ToolError> {
        match self.get(key) {
            None => Ok(None),
            Some(v) => v
                .as_f64()
                .map(Some)
                .ok_or_else(|| wrong_type(key, "a number", v)),
        }
    }

    /// Required number.
    pub fn f64(&self, key: &str) -> Result<f64, ToolError> {
        self.opt_f64(key)?
            .ok_or_else(|| Self::missing(key, "number"))
    }

    /// Required array of strings.
    pub fn str_array(&self, key: &str) -> Result<Vec<String>, ToolError> {
        match self.get(key) {
            None => Err(Self::missing(key, "string array")),
            Some(Value::Array(arr)) => collect_strings(key, arr),
            Some(v) => Err(wrong_type(key, "an array of strings", v)),
        }
    }

    /// Optional array of strings (absent → empty).
    pub fn opt_str_array(&self, key: &str) -> Result<Vec<String>, ToolError> {
        match self.get(key) {
            None => Ok(Vec::new()),
            Some(Value::Array(arr)) => collect_strings(key, arr),
            Some(v) => Err(wrong_type(key, "an array of strings", v)),
        }
    }

    /// Optional map of string → string, such as environment variables
    /// (absent → empty).
    pub fn opt_string_map(&self, key: &str) -> Result<Vec<(String, String)>, ToolError> {
        match self.get(key) {
            None => Ok(Vec::new()),
            Some(Value::Object(map)) => map
                .iter()
                .map(|(k, v)| {
                    v.as_str()
                        .map(|s| (k.clone(), s.to_string()))
                        .ok_or_else(|| {
                            invalid(format!(
                                "value for '{key}.{k}' must be a string; got {}",
                                describe_value(v)
                            ))
                        })
                })
                .collect(),
            Some(v) => Err(wrong_type(key, "an object of string values", v)),
        }
    }
}

fn collect_strings(key: &str, arr: &[Value]) -> Result<Vec<String>, ToolError> {
    arr.iter()
        .enumerate()
        .map(|(i, v)| {
            v.as_str().map(str::to_string).ok_or_else(|| {
                invalid(format!(
                    "'{key}[{i}]' must be a string; got {}",
                    describe_value(v)
                ))
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn msg(e: ToolError) -> String {
        match e {
            ToolError::InvalidArguments(m) => m,
            other => panic!("expected InvalidArguments, got {other:?}"),
        }
    }

    #[test]
    fn extracts_typed_fields() {
        let v = json!({"path": "a.txt", "recursive": true, "count": 3, "items": ["x", "y"], "ratio": 0.5, "delta": -4});
        let a = Args::new(&v).unwrap();
        assert_eq!(a.str("path").unwrap(), "a.txt");
        assert!(a.bool_or("recursive", false).unwrap());
        assert!(a.bool("recursive").unwrap());
        assert_eq!(a.u64_or("count", 0).unwrap(), 3);
        assert_eq!(a.u64("count").unwrap(), 3);
        assert_eq!(a.usize_or("count", 0).unwrap(), 3);
        assert_eq!(a.i64("delta").unwrap(), -4);
        assert_eq!(a.f64("ratio").unwrap(), 0.5);
        assert_eq!(a.str_array("items").unwrap(), vec!["x", "y"]);
        assert!(a.opt_str("missing").unwrap().is_none());
    }

    #[test]
    fn non_object_arguments_rejected_and_null_is_empty() {
        let bad = json!([1]);
        assert!(msg(Args::new(&bad).unwrap_err()).contains("must be a JSON object"));
        let null = Value::Null;
        let a = Args::new(&null).unwrap();
        assert!(a.opt_str("x").unwrap().is_none());
        assert_eq!(a.u64_or("n", 7).unwrap(), 7);
    }

    #[test]
    fn wrong_type_messages_name_field_and_value() {
        let v = json!({"path": 5, "flag": "yes", "n": "ten", "list": "a", "env": []});
        let a = Args::new(&v).unwrap();
        let e = msg(a.str("path").unwrap_err());
        assert!(
            e.contains("'path'") && e.contains("a string") && e.contains("integer 5"),
            "{e}"
        );
        let e = msg(a.bool_or("flag", false).unwrap_err());
        assert!(
            e.contains("'flag'") && e.contains("a boolean") && e.contains("\"yes\""),
            "{e}"
        );
        let e = msg(a.opt_u64("n").unwrap_err());
        assert!(e.contains("non-negative integer"), "{e}");
        let e = msg(a.opt_str_array("list").unwrap_err());
        assert!(e.contains("array of strings"), "{e}");
        let e = msg(a.opt_string_map("env").unwrap_err());
        assert!(e.contains("object of string values"), "{e}");
    }

    #[test]
    fn missing_required_fields_say_missing() {
        let v = json!({});
        let a = Args::new(&v).unwrap();
        assert!(msg(a.str("path").unwrap_err()).contains("missing required string 'path'"));
        assert!(msg(a.str_array("xs").unwrap_err()).contains("missing required string array 'xs'"));
        assert!(msg(a.u64("n").unwrap_err()).contains("missing required"));
        assert!(msg(a.i64("n").unwrap_err()).contains("missing required"));
        assert!(msg(a.f64("n").unwrap_err()).contains("missing required"));
        assert!(msg(a.bool("b").unwrap_err()).contains("missing required"));
    }

    #[test]
    fn null_counts_as_absent() {
        let v = json!({"a": null});
        let a = Args::new(&v).unwrap();
        assert!(a.opt_str("a").unwrap().is_none());
        assert!(a.opt_value("a").is_none());
        assert!(a.str("a").is_err());
        assert!(a.opt_str_array("a").unwrap().is_empty());
    }

    #[test]
    fn integers_accept_integral_floats_but_not_fractions_or_overflow() {
        let v = json!({"a": 30.0, "b": 1.5, "c": -1, "d": u64::MAX, "e": 1e3});
        let a = Args::new(&v).unwrap();
        assert_eq!(a.opt_u64("a").unwrap(), Some(30));
        assert_eq!(a.opt_u64("e").unwrap(), Some(1000));
        assert!(a.opt_u64("b").is_err());
        assert!(a.opt_u64("c").is_err());
        assert_eq!(a.opt_i64("c").unwrap(), Some(-1));
        assert_eq!(a.opt_u64("d").unwrap(), Some(u64::MAX));
        assert!(a.opt_i64("d").is_err());
        assert_eq!(a.opt_f64("b").unwrap(), Some(1.5));
        assert!(a.opt_f64("a").is_ok());
    }

    #[test]
    fn usize_or_uses_default_and_value() {
        let v = json!({"n": 12});
        let a = Args::new(&v).unwrap();
        assert_eq!(a.usize_or("n", 1).unwrap(), 12);
        assert_eq!(a.usize_or("m", 99).unwrap(), 99);
        let neg = json!({"n": -2});
        assert!(Args::new(&neg).unwrap().usize_or("n", 1).is_err());
    }

    #[test]
    fn opt_enum_lists_allowed_values() {
        let v = json!({"mode": "fast", "bad": "slow", "num": 3});
        let a = Args::new(&v).unwrap();
        assert_eq!(a.opt_enum("mode", &["fast", "safe"]).unwrap(), Some("fast"));
        assert_eq!(a.opt_enum("none", &["fast"]).unwrap(), None);
        let e = msg(a.opt_enum("bad", &["fast", "safe"]).unwrap_err());
        assert!(
            e.contains("\"fast\", \"safe\"") && e.contains("\"slow\""),
            "{e}"
        );
        assert!(a.opt_enum("num", &["fast"]).is_err());
    }

    #[test]
    fn str_array_reports_element_index() {
        let v = json!({"xs": ["a", 2, "c"]});
        let e = msg(Args::new(&v).unwrap().str_array("xs").unwrap_err());
        assert!(e.contains("xs[1]") && e.contains("integer 2"), "{e}");
    }

    #[test]
    fn string_map_parses_and_rejects_non_string_values() {
        let v = json!({"env": {"A": "1", "B": "two"}});
        let mut env = Args::new(&v).unwrap().opt_string_map("env").unwrap();
        env.sort();
        assert_eq!(
            env,
            vec![("A".into(), "1".into()), ("B".into(), "two".into())]
        );
        let bad = json!({"env": {"A": 1}});
        let e = msg(Args::new(&bad).unwrap().opt_string_map("env").unwrap_err());
        assert!(e.contains("env.A") && e.contains("integer 1"), "{e}");
    }

    #[test]
    fn long_values_are_truncated_in_messages() {
        let v = json!({"path": "x".repeat(10_000)});
        let a = Args::new(&v).unwrap();
        let e = msg(a.u64("path").unwrap_err());
        assert!(e.len() < 400, "{}", e.len());
        assert!(e.contains('…'));
    }

    #[test]
    fn accessors_do_not_panic_on_odd_values() {
        for odd in [
            json!(""),
            json!([]),
            json!({}),
            json!(1e300),
            json!(-0.0),
            json!(true),
        ] {
            let v = json!({"k": odd});
            let a = Args::new(&v).unwrap();
            let _ = a.str("k");
            let _ = a.opt_u64("k");
            let _ = a.opt_i64("k");
            let _ = a.opt_f64("k");
            let _ = a.usize_or("k", 0);
            let _ = a.opt_str_array("k");
            let _ = a.opt_string_map("k");
            let _ = a.opt_enum("k", &[]);
        }
    }
}
