//! Transfer Authorization Guard (Issue #1068).
//!
//! A reusable guard that validates whether a caller is authorized to transfer
//! a specific NFT.  This module is the canonical authorization check for all
//! transfer entry points in the contract.
//!
//! # Authorization hierarchy
//!
//! A caller is authorized if they satisfy **any** of the following conditions:
//!
//! 1. **Owner** — the caller is the current owner of the token (`from`).
//! 2. **Single-token approved** — the caller holds a token-level approval
//!    granted via the `approve` analogue (stored under `DataKey::Approval`).
//! 3. **Operator** — the caller is an operator approved for **all** tokens of
//!    the current owner (stored under `DataKey::OperatorApproval`).
//!
//! Unauthorized callers receive [`Error::Unauthorized`].
//!
//! # Usage
//!
//! ```rust,ignore
//! transfer_auth_guard::check_transfer_auth(&env, &caller, &from, token_id)?;
//! ```

use soroban_sdk::{Address, Env};

use crate::operator_approval;
use crate::token_approval;
use crate::token_owner_storage;
use crate::types::{Error, TokenId};

// ─── Primary entry point ──────────────────────────────────────────────────────

/// Validate that `caller` is authorized to transfer `token_id` from `from`.
///
/// Runs all authorization checks in order and returns the first error
/// encountered.  Performs `caller.require_auth()` before any checks so that
/// the authorization is always captured in the transaction envelope.
///
/// # Arguments
/// * `env`      — Contract environment.
/// * `caller`   — Address requesting the transfer.
/// * `from`     — Current owner of the token.
/// * `token_id` — Token to be transferred.
///
/// # Errors
/// | Error | Condition |
/// |-------|-----------|
/// | `TokenNotFound` | Token does not exist or `from` is not its owner. |
/// | `Unauthorized`  | `caller` is not the owner, approved address, or operator. |
pub fn check_transfer_auth(
    env: &Env,
    caller: &Address,
    from: &Address,
    token_id: TokenId,
) -> Result<(), Error> {
    // Require the caller to authenticate the transaction.
    caller.require_auth();

    // Verify the token exists and `from` is its current owner.
    token_owner_storage::verify_owner(env, token_id, from)?;

    // Check authorization hierarchy.
    if is_owner(caller, from)
        || is_token_approved(env, caller, token_id)
        || is_operator_approved(env, caller, from)
    {
        return Ok(());
    }

    Err(Error::Unauthorized)
}

// ─── Individual authorization checks ─────────────────────────────────────────

/// Return `true` if `caller` is the token's current owner (`from`).
///
/// Owner transfers are always permitted; no additional approval is needed.
pub fn is_owner(caller: &Address, from: &Address) -> bool {
    caller == from
}

/// Return `true` if `caller` holds a single-token approval for `token_id`.
///
/// This mirrors the ERC-721 `approve` model: the owner has explicitly granted
/// `caller` the right to transfer this specific token.
pub fn is_token_approved(env: &Env, caller: &Address, token_id: TokenId) -> bool {
    token_approval::get_approval(env, token_id)
        .map(|approved| &approved == caller)
        .unwrap_or(false)
}

/// Return `true` if `caller` is an operator approved for all of `owner`'s tokens.
///
/// This mirrors the ERC-721 `setApprovalForAll` model: the owner has delegated
/// full transfer authority over their entire portfolio to `caller`.
pub fn is_operator_approved(env: &Env, caller: &Address, owner: &Address) -> bool {
    operator_approval::is_operator(env, owner, caller)
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator_approval;
    use crate::token_approval;
    use crate::token_owner_storage;
    use crate::AtomicMintContract;
    use soroban_sdk::{testutils::Address as _, Address, Env};

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

    /// Mint a minimal token owned by `owner`.
    fn setup_token(env: &Env, token_id: TokenId, owner: &Address) {
        token_owner_storage::assign_owner(env, token_id, owner, token_id).unwrap();
    }

    // ── is_owner ──────────────────────────────────────────────────────────────

    #[test]
    fn owner_is_authorized() {
        with_contract(|env| {
            let owner = Address::generate(env);
            setup_token(env, 1, &owner);
            assert!(check_transfer_auth(env, &owner, &owner, 1).is_ok());
        });
    }

    #[test]
    fn non_owner_without_approval_is_rejected() {
        with_contract(|env| {
            let owner = Address::generate(env);
            let stranger = Address::generate(env);
            setup_token(env, 1, &owner);
            assert_eq!(
                check_transfer_auth(env, &stranger, &owner, 1),
                Err(Error::Unauthorized)
            );
        });
    }

    // ── is_token_approved ─────────────────────────────────────────────────────

    #[test]
    fn single_token_approved_address_is_authorized() {
        with_contract(|env| {
            let owner = Address::generate(env);
            let approved = Address::generate(env);
            setup_token(env, 1, &owner);
            token_approval::save_approval(env, 1, &approved);
            assert!(check_transfer_auth(env, &approved, &owner, 1).is_ok());
        });
    }

    #[test]
    fn approval_for_different_token_does_not_authorize() {
        with_contract(|env| {
            let owner = Address::generate(env);
            let approved = Address::generate(env);
            setup_token(env, 1, &owner);
            setup_token(env, 2, &owner);
            // Approved for token 2, not token 1.
            token_approval::save_approval(env, 2, &approved);
            assert_eq!(
                check_transfer_auth(env, &approved, &owner, 1),
                Err(Error::Unauthorized)
            );
        });
    }

    #[test]
    fn revoked_approval_does_not_authorize() {
        with_contract(|env| {
            let owner = Address::generate(env);
            let approved = Address::generate(env);
            setup_token(env, 1, &owner);
            token_approval::save_approval(env, 1, &approved);
            token_approval::remove_approval(env, 1);
            assert_eq!(
                check_transfer_auth(env, &approved, &owner, 1),
                Err(Error::Unauthorized)
            );
        });
    }

    // ── is_operator_approved ─────────────────────────────────────────────────

    #[test]
    fn operator_approved_for_all_is_authorized() {
        with_contract(|env| {
            let owner = Address::generate(env);
            let operator = Address::generate(env);
            setup_token(env, 1, &owner);
            operator_approval::save_operator(env, &owner, &operator);
            assert!(check_transfer_auth(env, &operator, &owner, 1).is_ok());
        });
    }

    #[test]
    fn revoked_operator_is_rejected() {
        with_contract(|env| {
            let owner = Address::generate(env);
            let operator = Address::generate(env);
            setup_token(env, 1, &owner);
            operator_approval::save_operator(env, &owner, &operator);
            operator_approval::remove_operator(env, &owner, &operator);
            assert_eq!(
                check_transfer_auth(env, &operator, &owner, 1),
                Err(Error::Unauthorized)
            );
        });
    }

    #[test]
    fn operator_approved_for_different_owner_is_rejected() {
        with_contract(|env| {
            let owner_a = Address::generate(env);
            let owner_b = Address::generate(env);
            let operator = Address::generate(env);
            setup_token(env, 1, &owner_a);
            // Operator is approved for owner_b's tokens, not owner_a's.
            operator_approval::save_operator(env, &owner_b, &operator);
            assert_eq!(
                check_transfer_auth(env, &operator, &owner_a, 1),
                Err(Error::Unauthorized)
            );
        });
    }

    // ── Token not found ───────────────────────────────────────────────────────

    #[test]
    fn returns_token_not_found_when_token_does_not_exist() {
        with_contract(|env| {
            let caller = Address::generate(env);
            let from = Address::generate(env);
            // Token 999 was never minted.
            assert_eq!(
                check_transfer_auth(env, &caller, &from, 999),
                Err(Error::TokenNotFound)
            );
        });
    }

    #[test]
    fn returns_token_not_found_when_from_is_not_owner() {
        with_contract(|env| {
            let real_owner = Address::generate(env);
            let fake_from = Address::generate(env);
            setup_token(env, 1, &real_owner);
            // `fake_from` claims to own the token but does not.
            assert_eq!(
                check_transfer_auth(env, &fake_from, &fake_from, 1),
                Err(Error::TokenNotFound)
            );
        });
    }

    // ── Helper functions ──────────────────────────────────────────────────────

    #[test]
    fn is_owner_returns_true_for_matching_addresses() {
        with_contract(|env| {
            let addr = Address::generate(env);
            assert!(is_owner(&addr, &addr));
        });
    }

    #[test]
    fn is_owner_returns_false_for_different_addresses() {
        with_contract(|env| {
            let a = Address::generate(env);
            let b = Address::generate(env);
            assert!(!is_owner(&a, &b));
        });
    }

    #[test]
    fn is_token_approved_returns_false_when_no_approval_set() {
        with_contract(|env| {
            let caller = Address::generate(env);
            assert!(!is_token_approved(env, &caller, 1));
        });
    }

    #[test]
    fn is_operator_approved_returns_false_when_no_operator_set() {
        with_contract(|env| {
            let owner = Address::generate(env);
            let operator = Address::generate(env);
            assert!(!is_operator_approved(env, &operator, &owner));
        });
    }
}
