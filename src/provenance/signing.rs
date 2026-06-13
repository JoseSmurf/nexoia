#![allow(dead_code)]

use serde_json::Value;
use std::convert::TryFrom;

pub fn canonical_json(data: &serde_json::Value) -> String {
    let mut output = String::new();
    write_canonical_json(data, &mut output);
    output
}

fn write_canonical_json(value: &Value, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(boolean) => output.push_str(if *boolean { "true" } else { "false" }),
        Value::Number(number) => output.push_str(&number.to_string()),
        Value::String(text) => {
            output
                .push_str(&serde_json::to_string(text).expect("string serialization must succeed"));
        }
        Value::Array(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical_json(item, output);
            }
            output.push(']');
        }
        Value::Object(map) => {
            output.push('{');
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();

            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key).expect("object key serialization must succeed"),
                );
                output.push(':');
                write_canonical_json(map.get(*key).expect("sorted key must exist"), output);
            }
            output.push('}');
        }
    }
}

pub fn length_prefixed_signing_message(fields: &[&[u8]]) -> Vec<u8> {
    let mut message = Vec::new();

    for field in fields {
        let len = u32::try_from(field.len()).expect("signing field length exceeds u32::MAX");
        message.extend_from_slice(&len.to_le_bytes());
        message.extend_from_slice(field);
    }

    message
}

#[cfg(test)]
mod tests {
    use super::{canonical_json, length_prefixed_signing_message};
    use serde_json::json;

    #[test]
    fn canonical_json_sorts_object_keys_recursively() {
        let value = json!({
            "b": 1,
            "a": {
                "d": 4,
                "c": 3
            },
            "arr": [
                {
                    "z": 1,
                    "y": 2
                }
            ]
        });

        let rendered = canonical_json(&value);
        assert_eq!(
            rendered,
            "{\"a\":{\"c\":3,\"d\":4},\"arr\":[{\"y\":2,\"z\":1}],\"b\":1}"
        );
    }

    #[test]
    fn length_prefixed_signing_message_uses_little_endian_lengths() {
        let message = length_prefixed_signing_message(&[b"ab", b"c"]);
        assert_eq!(message, vec![2, 0, 0, 0, b'a', b'b', 1, 0, 0, 0, b'c']);
    }
}
