use rand::Rng;

/// Generate a 6-digit numeric OTP.
pub fn generate_otp() -> String {
    let mut rng = rand::thread_rng();
    format!("{:06}", rng.gen_range(0..1_000_000))
}

/// Validate that an OTP string is exactly 6 ASCII digits.
pub fn validate_otp_format(otp: &str) -> bool {
    otp.len() == 6 && otp.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_generate_otp_is_six_digits() {
        let otp = generate_otp();
        assert_eq!(otp.len(), 6);
        assert!(otp.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_otp_is_numeric() {
        let otp = generate_otp();
        assert!(otp.parse::<u64>().is_ok());
    }

    #[test]
    fn test_generate_otp_varies() {
        let mut seen = HashSet::new();
        for _ in 0..100 {
            seen.insert(generate_otp());
        }
        // With 100 attempts across 1M possibilities, we should see multiple unique values
        assert!(seen.len() > 1);
    }

    #[test]
    fn test_validate_otp_format_valid() {
        assert!(validate_otp_format("000000"));
        assert!(validate_otp_format("123456"));
        assert!(validate_otp_format("999999"));
        assert!(validate_otp_format("000001"));
    }

    #[test]
    fn test_validate_otp_format_too_short() {
        assert!(!validate_otp_format("12345"));
        assert!(!validate_otp_format(""));
        assert!(!validate_otp_format("123"));
    }

    #[test]
    fn test_validate_otp_format_too_long() {
        assert!(!validate_otp_format("1234567"));
        assert!(!validate_otp_format("12345678"));
    }

    #[test]
    fn test_validate_otp_format_non_numeric() {
        assert!(!validate_otp_format("abcdef"));
        assert!(!validate_otp_format("12ab56"));
        assert!(!validate_otp_format("12345a"));
    }

    #[test]
    fn test_validate_otp_format_special_chars() {
        assert!(!validate_otp_format("12-456"));
        assert!(!validate_otp_format("12 456"));
        assert!(!validate_otp_format("12345!"));
    }
}
