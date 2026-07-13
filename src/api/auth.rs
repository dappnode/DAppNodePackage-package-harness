use axum::http::HeaderMap;
use subtle::ConstantTimeEq;

pub fn bearer_is_valid(headers: &HeaderMap, expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    let Some(provided) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    let expected_bytes = expected.as_bytes();
    let provided_bytes = provided.as_bytes();
    if expected_bytes.len() != provided_bytes.len() {
        let mut padded = vec![0_u8; expected_bytes.len().max(provided_bytes.len())];
        let copy_length = provided_bytes.len().min(padded.len());
        padded[..copy_length].copy_from_slice(&provided_bytes[..copy_length]);
        let _comparison = expected_bytes.ct_eq(&padded[..expected_bytes.len()]);
        return false;
    }
    bool::from(expected_bytes.ct_eq(provided_bytes))
}
