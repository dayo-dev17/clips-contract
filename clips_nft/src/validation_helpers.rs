//! Validation Helper Utilities (Issue #1087).
//!
//! Shared, reusable helper functions for common validation operations used
//! across the contract's validators and guards.  Centralising these helpers
//! eliminates duplicated validation logic and ensures every module uses the
//! same error definitions from [`crate::types::Error`].
//!
//! # Helpers
//!
//! | Helper | Validates |
//! |--------|-----------|
//! | [`require_non_zero_u32`] | u32 must be greater than zero. |
//! | [`validate_basis_points`] | BPS value in `[0, max_bps]`. |
//! | [`validate_address_not_contract`] | Address must not be the contract itself. |
//! | [`validate_address_not_blacklisted`] | Address must not be blacklisted. |
//! | [`validate_string_non_empty`] | String must have at least one character. |
//! | [`validate_string_max_len`] | String length must not exceed a maximum. |
//! | [`validate_uri_scheme`] | URI must begin with a supported protocol. |
//! | [`validate_token_exists`] | Token must have an on-chain ownership record. |
//! | [`validate_within_range_u32`] | u32 value must be within `[min, max]`. |
//! | [`validate_not_zero_address`] | Option<Address> must be `Some(_)`. |

use soroban_sdk::{Address, Env, String};

use crate::blacklist;
use crate::token_owner_storage;
use crate::types::{Error, TokenId};

// ─── Numeric helpers ──────────────────────────────────────────────────────────

/// Validate that `value` is strictly greater than zero.
///
/// # Errors
/// Returns [`Error::InvalidConfig`] when `value` is `0`.
pub fn require_non_zero_u32(value: u32) -> Result<(), Error> {
    if value == 0 {
        return Err(Error::InvalidConfig);
    }
    Ok(())
}

/// Validate that `bps` is within `[0, max_bps]` (inclusive).
///
/// Basis points represent a percentage where 10 000 = 100 %.  Values above
/// `max_bps` are rejected to prevent economically invalid configurations.
///
/// # Errors
/// Returns [`Error::InvalidBasisPoints`] when `bps > max_bps`.
pub fn validate_basis_points(bps: u32, max_bps: u32) -> Result<(), Error> {
    if bps > max_bps {
        return Err(Error::InvalidBasisPoints);
    }
    Ok(())
}

/// Validate that `value` is within `[min, max]` (inclusive).
///
/// # Errors
/// Returns [`Error::InvalidConfig`] when `value < min || value > max`.
pub fn validate_within_range_u32(value: u32, min: u32, max: u32) -> Result<(), Error> {
    if value < min || value > max {
        return Err(Error::InvalidConfig);
    }
    Ok(())
}

// ─── Address helpers ──────────────────────────────────────────────────────────

/// Validate that `address` is not the contract's own address.
///
/// The contract cannot own NFTs or receive payments to itself.  Use this helper
/// wherever a recipient or owner address is accepted from external input.
///
/// # Errors
/// Returns [`Error::InvalidAddress`] when `address` equals the current contract.
pub fn validate_address_not_contract(env: &Env, address: &Address) -> Result<(), Error> {
    if *address == env.current_contract_address() {
        return Err(Error::InvalidAddress);
    }
    Ok(())
}

/// Validate that `address` is not on the contract blacklist.
///
/// # Errors
/// Returns [`Error::InvalidAddress`] when `address` has been blacklisted.
pub fn validate_address_not_blacklisted(env: &Env, address: &Address) -> Result<(), Error> {
    if blacklist::is_blacklisted(env, address) {
        return Err(Error::InvalidAddress);
    }
    Ok(())
}

/// Validate that an `Option<Address>` is `Some(_)` (i.e. the address is set).
///
/// # Errors
/// Returns [`Error::InvalidAddress`] when `addr` is `None`.
pub fn validate_not_zero_address(addr: &Option<Address>) -> Result<(), Error> {
    if addr.is_none() {
        return Err(Error::InvalidAddress);
    }
    Ok(())
}

// ─── String / URI helpers ─────────────────────────────────────────────────────

/// Validate that a `String` is non-empty (length > 0).
///
/// # Errors
/// Returns [`Error::InvalidURI`] when `s` has length `0`.
pub fn validate_string_non_empty(s: &String) -> Result<(), Error> {
    if s.len() == 0 {
        return Err(Error::InvalidURI);
    }
    Ok(())
}

/// Validate that a `String` does not exceed `max_len` characters.
///
/// # Errors
/// Returns [`Error::MetadataSizeTooLarge`] when `s.len() > max_len`.
pub fn validate_string_max_len(s: &String, max_len: u32) -> Result<(), Error> {
    if s.len() > max_len {
        return Err(Error::MetadataSizeTooLarge);
    }
    Ok(())
}

/// Validate that a URI begins with one of the supported protocol schemes.
///
/// Accepted schemes: `https://`, `ipfs://`, `ar://`.
///
/// # Errors
/// Returns [`Error::UnsupportedProtocol`] when the URI starts with an
/// unrecognised scheme.
/// Returns [`Error::MalformedUrl`] when the URI is empty.
pub fn validate_uri_scheme(env: &Env, uri: &String) -> Result<(), Error> {
    if uri.len() == 0 {
        return Err(Error::MalformedUrl);
    }

    // Supported scheme prefixes — order matters: check longer prefixes first.
    let schemes: &[&str] = &["https://", "ipfs://", "ar://"];

    for scheme in schemes {
        let scheme_str = soroban_sdk::String::from_str(env, scheme);
        if starts_with(uri, &scheme_str) {
            return Ok(());
        }
    }

    Err(Error::UnsupportedProtocol)
}

// ─── Token helpers ────────────────────────────────────────────────────────────

/// Validate that `token_id` has an on-chain ownership record.
///
/// # Errors
/// Returns [`Error::TokenNotFound`] when no ownership record exists for
/// `token_id`.
pub fn validate_token_exists(env: &Env, token_id: TokenId) -> Result<(), Error> {
    if !token_owner_storage::has_owner(env, token_id) {
        return Err(Error::TokenNotFound);
    }
    Ok(())
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/// Return `true` if `haystack` starts with `prefix` using byte-level comparison.
///
/// This is a pure helper; it does not allocate.
fn starts_with(haystack: &String, prefix: &String) -> bool {
    let prefix_len = prefix.len();
    if haystack.len() < prefix_len {
        return false;
    }
    // Compare character by character up to prefix_len.
    for i in 0..prefix_len {
        if haystack.get(i) != prefix.get(i) {
            return false;
        }
    }
    true
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blacklist;
    use crate::token_owner_storage;
    use crate::AtomicMintContract;
    use soroban_sdk::{testutils::Address as _, Address, Env, String};

    /// Helper — register the contract and run `f` inside its context.
    fn with_contract<F, R>(f: F) -> R
    where
        F: FnOnce(&Env) -> R,
    {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(AtomicMintContract, ());
        env.as_contract(&contract_id, || f(&env))
    }

    // ── require_non_zero_u32 ──────────────────────────────────────────────────

    #[test]
    fn non_zero_u32_passes_for_positive_value() {
        assert!(require_non_zero_u32(1).is_ok());
        assert!(require_non_zero_u32(u32::MAX).is_ok());
    }

    #[test]
    fn non_zero_u32_fails_for_zero() {
        assert_eq!(require_non_zero_u32(0), Err(Error::InvalidConfig));
    }

    // ── validate_basis_points ─────────────────────────────────────────────────

    #[test]
    fn basis_points_passes_for_zero() {
        assert!(validate_basis_points(0, 10_000).is_ok());
    }

    #[test]
    fn basis_points_passes_at_maximum() {
        assert!(validate_basis_points(10_000, 10_000).is_ok());
    }

    #[test]
    fn basis_points_fails_above_maximum() {
        assert_eq!(
            validate_basis_points(10_001, 10_000),
            Err(Error::InvalidBasisPoints)
        );
    }

    #[test]
    fn basis_points_respects_custom_maximum() {
        assert!(validate_basis_points(500, 1_000).is_ok());
        assert_eq!(
            validate_basis_points(1_001, 1_000),
            Err(Error::InvalidBasisPoints)
        );
    }

    // ── validate_within_range_u32 ─────────────────────────────────────────────

    #[test]
    fn range_passes_at_boundaries() {
        assert!(validate_within_range_u32(1, 1, 10).is_ok());
        assert!(validate_within_range_u32(10, 1, 10).is_ok());
        assert!(validate_within_range_u32(5, 1, 10).is_ok());
    }

    #[test]
    fn range_fails_below_minimum() {
        assert_eq!(
            validate_within_range_u32(0, 1, 10),
            Err(Error::InvalidConfig)
        );
    }

    #[test]
    fn range_fails_above_maximum() {
        assert_eq!(
            validate_within_range_u32(11, 1, 10),
            Err(Error::InvalidConfig)
        );
    }

    // ── validate_address_not_contract ─────────────────────────────────────────

    #[test]
    fn address_not_contract_passes_for_regular_address() {
        with_contract(|env| {
            let addr = Address::generate(env);
            assert!(validate_address_not_contract(env, &addr).is_ok());
        });
    }

    #[test]
    fn address_not_contract_fails_for_contract_itself() {
        with_contract(|env| {
            let contract = env.current_contract_address();
            assert_eq!(
                validate_address_not_contract(env, &contract),
                Err(Error::InvalidAddress)
            );
        });
    }

    // ── validate_address_not_blacklisted ──────────────────────────────────────

    #[test]
    fn address_not_blacklisted_passes_for_clean_address() {
        with_contract(|env| {
            let addr = Address::generate(env);
            assert!(validate_address_not_blacklisted(env, &addr).is_ok());
        });
    }

    #[test]
    fn address_not_blacklisted_fails_for_blacklisted_address() {
        with_contract(|env| {
            let addr = Address::generate(env);
            blacklist::add_wallet(env, &addr);
            assert_eq!(
                validate_address_not_blacklisted(env, &addr),
                Err(Error::InvalidAddress)
            );
        });
    }

    #[test]
    fn address_not_blacklisted_passes_after_removal() {
        with_contract(|env| {
            let addr = Address::generate(env);
            blacklist::add_wallet(env, &addr);
            blacklist::remove_wallet(env, &addr);
            assert!(validate_address_not_blacklisted(env, &addr).is_ok());
        });
    }

    // ── validate_not_zero_address ─────────────────────────────────────────────

    #[test]
    fn not_zero_address_passes_for_some() {
        let env = Env::default();
        let addr = Address::generate(&env);
        assert!(validate_not_zero_address(&Some(addr)).is_ok());
    }

    #[test]
    fn not_zero_address_fails_for_none() {
        assert_eq!(validate_not_zero_address(&None), Err(Error::InvalidAddress));
    }

    // ── validate_string_non_empty ─────────────────────────────────────────────

    #[test]
    fn string_non_empty_passes_for_non_empty_string() {
        let env = Env::default();
        let s = String::from_str(&env, "hello");
        assert!(validate_string_non_empty(&s).is_ok());
    }

    #[test]
    fn string_non_empty_fails_for_empty_string() {
        let env = Env::default();
        let s = String::from_str(&env, "");
        assert_eq!(validate_string_non_empty(&s), Err(Error::InvalidURI));
    }

    // ── validate_string_max_len ───────────────────────────────────────────────

    #[test]
    fn string_max_len_passes_at_limit() {
        let env = Env::default();
        let s = String::from_str(&env, "hello"); // 5 chars
        assert!(validate_string_max_len(&s, 5).is_ok());
    }

    #[test]
    fn string_max_len_fails_above_limit() {
        let env = Env::default();
        let s = String::from_str(&env, "hello world"); // 11 chars
        assert_eq!(
            validate_string_max_len(&s, 5),
            Err(Error::MetadataSizeTooLarge)
        );
    }

    // ── validate_uri_scheme ───────────────────────────────────────────────────

    #[test]
    fn uri_scheme_passes_for_https() {
        with_contract(|env| {
            let uri = String::from_str(env, "https://example.com/metadata.json");
            assert!(validate_uri_scheme(env, &uri).is_ok());
        });
    }

    #[test]
    fn uri_scheme_passes_for_ipfs() {
        with_contract(|env| {
            let uri = String::from_str(env, "ipfs://QmExampleHash");
            assert!(validate_uri_scheme(env, &uri).is_ok());
        });
    }

    #[test]
    fn uri_scheme_passes_for_arweave() {
        with_contract(|env| {
            let uri = String::from_str(env, "ar://ExampleTxId");
            assert!(validate_uri_scheme(env, &uri).is_ok());
        });
    }

    #[test]
    fn uri_scheme_fails_for_unsupported_scheme() {
        with_contract(|env| {
            let uri = String::from_str(env, "ftp://example.com/file");
            assert_eq!(
                validate_uri_scheme(env, &uri),
                Err(Error::UnsupportedProtocol)
            );
        });
    }

    #[test]
    fn uri_scheme_fails_for_empty_uri() {
        with_contract(|env| {
            let uri = String::from_str(env, "");
            assert_eq!(validate_uri_scheme(env, &uri), Err(Error::MalformedUrl));
        });
    }

    // ── validate_token_exists ─────────────────────────────────────────────────

    #[test]
    fn token_exists_passes_for_minted_token() {
        with_contract(|env| {
            let owner = Address::generate(env);
            token_owner_storage::assign_owner(env, 1, &owner, 1).unwrap();
            assert!(validate_token_exists(env, 1).is_ok());
        });
    }

    #[test]
    fn token_exists_fails_for_unminted_token() {
        with_contract(|env| {
            assert_eq!(validate_token_exists(env, 999), Err(Error::TokenNotFound));
        });
    }

    #[test]
    fn token_exists_fails_after_owner_removed() {
        with_contract(|env| {
            let owner = Address::generate(env);
            token_owner_storage::assign_owner(env, 1, &owner, 1).unwrap();
            token_owner_storage::remove_owner(env, 1);
            assert_eq!(validate_token_exists(env, 1), Err(Error::TokenNotFound));
        });
    }
}
