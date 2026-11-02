//! A small JSON-Schema subset checker for tool arguments: object, array,
//! string, integer, `properties`, `required`, `additionalProperties: false`,
//! `enum` and `minimum`. Nested arguments get the same checks as top-level ones.

use serde_json::Value;

/// Checks `v` against `schema`. The error names the offending path.
pub(crate) fn validate(schema: &Value, v: &Value, path: &str) -> Result<(), String> {
    match schema["type"].as_str() {
        Some("object") => {
            let obj = v.as_object().ok_or_else(|| format!("`{path}` must be an object"))?;
            for r in schema["required"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                if !obj.contains_key(r) {
                    return Err(format!("missing argument `{path}.{r}`"));
                }
            }
            for (k, child) in obj {
                match schema["properties"].get(k) {
                    Some(sub) => validate(sub, child, &format!("{path}.{k}"))?,
                    None if schema["additionalProperties"] == Value::Bool(false) => {
                        return Err(format!("unknown argument `{path}.{k}`"));
                    }
                    None => {}
                }
            }
            Ok(())
        }
        Some("array") => {
            let items = v.as_array().ok_or_else(|| format!("`{path}` must be an array"))?;
            items
                .iter()
                .enumerate()
                .try_for_each(|(i, item)| validate(&schema["items"], item, &format!("{path}[{i}]")))
        }
        Some("string") => {
            let s = v.as_str().ok_or_else(|| format!("`{path}` must be a string"))?;
            match schema["enum"].as_array() {
                Some(allowed) if !allowed.iter().any(|a| a == s) => Err(format!("`{path}` is not an allowed value")),
                _ => Ok(()),
            }
        }
        Some("integer") => {
            let n = v.as_i64().ok_or_else(|| format!("`{path}` must be an integer"))?;
            match schema["minimum"].as_i64() {
                Some(min) if n < min => Err(format!("`{path}` must be at least {min}")),
                _ => Ok(()),
            }
        }
        _ => Ok(()),
    }
}
