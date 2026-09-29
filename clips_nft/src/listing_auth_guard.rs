//! Listing Authorization Guard (Issue #1070).
//!
//! Verifies whether a caller is authorized to create or modify a marketplace
//! listing for a specific NFT.  Guards listing operations against unauthorized
//! actors and invalid token states.
//!
//! # Authorization requirements
//!
//! A caller may create or modify a listing only when **all** of the following
//! hold:
//!
//! 1. **Ownership or approved authority** — the caller is either:
//!    - The current token owner, **or**
//!    - An address with a single-token approval, **or**
//!    - An operator approved for all of the owner's tokens.
//! 2. **Token is not frozen** — frozen (soulbound) tokens cannot be listed
//!    because they are permanently non-transferable.
//! 3. **Token exists** — the referenced token ID must have an ownership record.
//!
//! # Usage
//!
//! ```rust,ignore
//! listing_auth_guard::check_listing_auth(&env, &caller, token_id)?;
//! ```

use soroban_sdk::{Address, Env};

use crate::frozen_token;
use crate::operator_approval;
use crate::token_approval;
use crate::token_owner_storage;
use crate::types::{Error, TokenId};

// ─── Primary entry point ──────────────────────────────────────────────────────

/// Validate that `caller` is authorized to create or modify a listing for
/// `token_id`.
///
/// Performs all listing pre-condition checks in order:
/// 1. Token exists (returns `TokenNotFound` if not).
/// 2. Token is not frozen (returns `Unauthorized` if frozen).
/// 3. Caller is the owner, a token-level approved address, or an operator
///    (returns `Unauthorized` if none of these).
///
/// # Arguments
/// * `env`      — Contract environment.
/// * `caller`   — Address attempting to create or modify the listing.
/// * `token_id` — Token to be listed.
///
/// # Errors
/// | Error | Condition |
/// |-------|-----------|
/// | `TokenNotFound` | Token does not exist. |
/// | `Unauthorized`  | Token is frozen, or `caller` lacks listing authority. |
pub fn check_listing_auth(
    env: &Env,
    caller: &Address,
    token_id: TokenId,
) -> Result<(), Error> {
    // Require the caller to authenticate the transaction.
    caller.require_auth();

    // 1. Verify the token exists and retrieve its owner.
    let owner = token_owner_storage::get_owner(env, token_id)?;

    // 2. Verify the token state allows listing.
    check_token_listable(env, token_id)?;

    // 3. Verify the caller has authority over this token.
    check_caller_can_list(env, caller, &owner, token_id)?;

    Ok(())
}

// ─── Token state validation ───────────────────────────────────────────────────

/// Ensure the token's current state permits listing.
///
/// A token may not be listed if it is frozen (soulbound), as it cannot change
/// hands regardless of who creates the listing.
///
/// # Errors
/// Returns [`Error::Unauthorized`] if the token is frozen.
pub fn check_token_listable(env: &Env, token_id: TokenId) -> Result<(), Error> {
    if frozen_token::is_frozen(env, token_id) {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

// ─── Caller authorization ─────────────────────────────────────────────────────

/// Validate that `caller` is authorized to list `token_id`.
///
/// Authorization is granted if `caller` is:
/// 1. The current `owner` of the token.
/// 2. The address with a single-token approval for `token_id`.
/// 3. An operator approved for all of `owner`'s tokens.
///
/// # Errors
/// Returns [`Error::Unauthorized`] if none of the above conditions is met.
pub fn check_caller_can_list(
    env: &Env,
    caller: &Address,
    owner: &Address,
    token_id: TokenId,
) -> Result<(), Error> {
    // 1. Owner may always list their own token.
    if caller == owner {
        return Ok(());
    }

    // 2. Single-token approved address.
    if let Some(approved) = token_approval::get_approval(env, token_id) {
        if &approved == caller {
            return Ok(());
        }
    }

    // 3. Operator approved for all tokens of `owner`.
    if operator_approval::is_operator(env, owner, caller) {
        return Ok(());
    }

    Err(Error::Unauthorized)
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frozen_token;
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

    // ── Ownership authorization ───────────────────────────────────────────────

    #[test]
    fn owner_can_create_listing() {
        with_contract(|env| {
            let owner = Address::generate(env);
            setup_token(env, 1, &owner);
            assert!(check_listing_auth(env, &owner, 1).is_ok());
        });
    }

    #[test]
    fn non_owner_without_approval_is_rejected() {
        with_contract(|env| {
            let owner = Address::generate(env);
            let stranger = Address::generate(env);
            setup_token(env, 1, &owner);
            assert_eq!(
                check_listing_auth(env, &stranger, 1),
                Err(Error::Unauthorized)
            );
        });
    }

    // ── Single-token approval ─────────────────────────────────────────────────

    #[test]
    fn approved_address_can_create_listing() {
        with_contract(|env| {
            let owner = Address::generate(env);
            let approved = Address::generate(env);
            setup_token(env, 1, &owner);
            token_approval::save_approval(env, 1, &approved);
            assert!(check_listing_auth(env, &approved, 1).is_ok());
        });
    }

    #[test]
    fn revoked_approval_cannot_create_listing() {
        with_contract(|env| {
            let owner = Address::generate(env);
            let approved = Address::generate(env);
            setup_token(env, 1, &owner);
            token_approval::save_approval(env, 1, &approved);
            token_approval::remove_approval(env, 1);
            assert_eq!(
                check_listing_auth(env, &approved, 1),
                Err(Error::Unauthorized)
            );
        });
    }

    #[test]
    fn approval_for_different_token_does_not_authorize_listing() {
        with_contract(|env| {
            let owner = Address::generate(env);
            let approved = Address::generate(env);
            setup_token(env, 1, &owner);
            setup_token(env, 2, &owner);
            token_approval::save_approval(env, 2, &approved);
            assert_eq!(
                check_listing_auth(env, &approved, 1),
                Err(Error::Unauthorized)
            );
        });
    }

    // ── Operator approval ─────────────────────────────────────────────────────

    #[test]
    fn operator_can_create_listing() {
        with_contract(|env| {
            let owner = Address::generate(env);
            let operator = Address::generate(env);
            setup_token(env, 1, &owner);
            operator_approval::save_operator(env, &owner, &operator);
            assert!(check_listing_auth(env, &operator, 1).is_ok());
        });
    }

    #[test]
    fn revoked_operator_cannot_create_listing() {
        with_contract(|env| {
            let owner = Address::generate(env);
            let operator = Address::generate(env);
            setup_token(env, 1, &owner);
            operator_approval::save_operator(env, &owner, &operator);
            operator_approval::remove_operator(env, &owner, &operator);
            assert_eq!(
                check_listing_auth(env, &operator, 1),
                Err(Error::Unauthorized)
            );
        });
    }

    #[test]
    fn operator_approved_for_different_owner_cannot_list() {
        with_contract(|env| {
            let owner_a = Address::generate(env);
            let owner_b = Address::generate(env);
            let operator = Address::generate(env);
            setup_token(env, 1, &owner_a);
            // Operator approved for owner_b, not owner_a.
            operator_approval::save_operator(env, &owner_b, &operator);
            assert_eq!(
                check_listing_auth(env, &operator, 1),
                Err(Error::Unauthorized)
            );
        });
    }

    // ── Token state validation ────────────────────────────────────────────────

    #[test]
    fn frozen_token_cannot_be_listed_by_owner() {
        with_contract(|env| {
            let owner = Address::generate(env);
            setup_token(env, 1, &owner);
            frozen_token::freeze_token(env, 1);
            assert_eq!(
                check_listing_auth(env, &owner, 1),
                Err(Error::Unauthorized)
            );
        });
    }

    #[test]
    fn frozen_token_cannot_be_listed_by_approved() {
        with_contract(|env| {
            let owner = Address::generate(env);
            let approved = Address::generate(env);
            setup_token(env, 1, &owner);
            token_approval::save_approval(env, 1, &approved);
            frozen_token::freeze_token(env, 1);
            assert_eq!(
                check_listing_auth(env, &approved, 1),
                Err(Error::Unauthorized)
            );
        });
    }

    #[test]
    fn unfrozen_token_can_be_listed_again() {
        with_contract(|env| {
            let owner = Address::generate(env);
            setup_token(env, 1, &owner);
            frozen_token::freeze_token(env, 1);
            frozen_token::unfreeze_token(env, 1);
            assert!(check_listing_auth(env, &owner, 1).is_ok());
        });
    }

    #[test]
    fn check_token_listable_passes_for_non_frozen_token() {
        with_contract(|env| {
            let owner = Address::generate(env);
            setup_token(env, 1, &owner);
            assert!(check_token_listable(env, 1).is_ok());
        });
    }

    #[test]
    fn check_token_listable_fails_for_frozen_token() {
        with_contract(|env| {
            let owner = Address::generate(env);
            setup_token(env, 1, &owner);
            frozen_token::freeze_token(env, 1);
            assert_eq!(check_token_listable(env, 1), Err(Error::Unauthorized));
        });
    }

    // ── Token existence ───────────────────────────────────────────────────────

    #[test]
    fn listing_nonexistent_token_returns_token_not_found() {
        with_contract(|env| {
            let caller = Address::generate(env);
            assert_eq!(
                check_listing_auth(env, &caller, 999),
                Err(Error::TokenNotFound)
            );
        });
    }
}
