//! Canonical federation principal-address grammar shared by the wire and the
//! workspace binding substrate.

/// Validate the logical two-part form used on the wire.
pub(crate) fn valid_principal_address(network_id: &str, principal_id: &str) -> bool {
    valid_network_id(network_id) && valid_principal_id(principal_id)
}

/// Validate the compact form stored in a `native-principal` binding.
#[cfg(test)]
pub(crate) fn valid_principal_binding(value: &str) -> bool {
    value
        .split_once('/')
        .is_some_and(|(network_id, principal_id)| valid_principal_address(network_id, principal_id))
}

fn valid_network_id(value: &str) -> bool {
    value == "native"
        || value.strip_prefix("dns:").is_some_and(valid_dns_name)
        || value.strip_prefix("key:").is_some_and(|thumbprint| {
            thumbprint.len() == 43
                && thumbprint
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
}

fn valid_principal_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.' | b'~'))
}

fn valid_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            let bytes = label.as_bytes();
            (1..=63).contains(&bytes.len())
                && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
                && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_each_documented_network_authority() {
        assert!(valid_principal_binding("native/A"));
        assert!(valid_principal_binding("dns:example.com/p_01J.foo~9"));
        assert!(valid_principal_binding(&format!(
            "key:{}/z9",
            "A".repeat(43)
        )));
    }

    #[test]
    fn enforces_dns_and_key_authority_canonicality() {
        for invalid in [
            "dns:/a",
            "dns:Example.com/a",
            "dns:-bad.example/a",
            "dns:bad..example/a",
            "dns:bad.example./a",
            "key:short/a",
            "other:example/a",
        ] {
            assert!(!valid_principal_binding(invalid), "{invalid}");
        }
        assert!(!valid_principal_binding(&format!(
            "key:{}/a",
            "A".repeat(44)
        )));
    }

    #[test]
    fn enforces_principal_edges_characters_and_bounds() {
        for invalid in [
            "native/",
            "native/_edge",
            "native/edge-",
            "native/a/b",
            "native/a:b",
            "native/a%20b",
        ] {
            assert!(!valid_principal_binding(invalid), "{invalid}");
        }
        assert!(valid_principal_binding(&format!(
            "native/{}",
            "a".repeat(64)
        )));
        assert!(!valid_principal_binding(&format!(
            "native/{}",
            "a".repeat(65)
        )));
    }

    #[test]
    fn enforces_dns_octet_bounds() {
        let label = "a".repeat(63);
        let longest = format!("{label}.{label}.{label}.{}", "a".repeat(61));
        assert_eq!(longest.len(), 253);
        assert!(valid_principal_binding(&format!("dns:{longest}/a")));
        assert!(!valid_principal_binding(&format!("dns:{longest}.a/a")));
        assert!(!valid_principal_binding(&format!(
            "dns:{}/a",
            "a".repeat(64)
        )));
    }
}
