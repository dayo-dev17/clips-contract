//! Pause Guard (Issue #1073).
//!
//! Prevents protected contract operations from executing while the contract is
//! paused.  Emergency operations that must remain accessible during a pause
//! (e.g. admin un-pause) are explicitly permitted via [`check_emergency_allowed`].
//!
//! # Guard functions
//!
//! | Function | Purpose |
//! |----------|---------|
//! | [`require_not_paused`] | Reject any state-changing call while paused. |
//! | [`require_paused`] | Reject calls that only make sense while paused (e.g. `unpause`). |
//! | [`check_emergency_allowed`] | Allow an explicit set of emergency operations through even when paused. |
//!
//! # Usage
//!
//! ```rust,ignore
//! // Normal protected operation — must fail while paused.
//! pause_guard::require_not_paused(&env)?;
//!
//! // Emergency operation — always allowed regardless of pause state.
//! pause_guard::check_emergency_allowed(op, &EMERGENCY_OPS)?;
//! ```

use soroban_sdk::Env;

use crate::pause_state::{get_pause_state, save_pause_state};
use crate::types::Error;

// ─── Permitted emergency operation identifiers ────────────────────────────────

/// Symbolic constant representing the "unpause" emergency operation.
///
/// Pass this (or a slice containing it) to [`check_emergency_allowed`] to
/// express that the unpause entry-point is always permitted even while paused.
pub const OP_UNPAUSE: u32 = 1;

/// Symbolic constant representing an admin-override emergency operation.
pub const OP_ADMIN_OVERRIDE: u32 = 2;

// ─── Primary guard functions ──────────────────────────────────────────────────

/// Reject the current invocation if the contract is paused.
///
/// Call this at the top of every normal state-changing function to prevent
/// execution while the contract is in the paused state.
///
/// # Errors
/// Returns [`Error::ContractPaused`] if the contract is paused.
pub fn require_not_paused(env: &Env) -> Result<(), Error> {
    if get_pause_state(env) {
        return Err(Error::ContractPaused);
    }
    Ok(())
}

/// Reject the current invocation if the contract is **not** paused.
///
/// Use this as the guard for operations that are only valid when the contract
/// is already paused — for example, an `unpause` entry point.
///
/// # Errors
/// Returns [`Error::NotPaused`] if the contract is not currently paused.
pub fn require_paused(env: &Env) -> Result<(), Error> {
    if !get_pause_state(env) {
        return Err(Error::NotPaused);
    }
    Ok(())
}

/// Allow an explicitly-listed emergency operation through regardless of pause.
///
/// Certain operations (e.g. un-pausing the contract, admin overrides) must
/// remain executable even while the contract is paused.  Pass the numeric
/// identifier of the requested operation and the slice of permitted identifiers
/// to this function; it returns `Ok(())` if the operation is on the allow-list
/// and `Err(Error::ContractPaused)` otherwise.
///
/// # Arguments
/// * `operation`        — Identifier of the operation being attempted.
/// * `allowed_ops`      — Slice of operation identifiers that are always permitted.
///
/// # Errors
/// Returns [`Error::ContractPaused`] when the operation is **not** in
/// `allowed_ops` and the contract is currently paused.
///
/// # Example
/// ```rust,ignore
/// // Always allow OP_UNPAUSE and OP_ADMIN_OVERRIDE through.
/// const EMERGENCY: &[u32] = &[pause_guard::OP_UNPAUSE, pause_guard::OP_ADMIN_OVERRIDE];
/// pause_guard::check_emergency_allowed(&env, OP_UNPAUSE, EMERGENCY)?;
/// ```
pub fn check_emergency_allowed(
    env: &Env,
    operation: u32,
    allowed_ops: &[u32],
) -> Result<(), Error> {
    // If the operation is explicitly permitted, allow it regardless of pause.
    if allowed_ops.contains(&operation) {
        return Ok(());
    }
    // Otherwise fall back to the normal not-paused check.
    require_not_paused(env)
}

// ─── Convenience helpers ──────────────────────────────────────────────────────

/// Pause the contract.  Convenience wrapper around [`save_pause_state`].
///
/// This does **not** perform any authorization check — callers are responsible
/// for verifying admin identity before invoking this helper.
pub fn pause(env: &Env) {
    save_pause_state(env, true);
}

/// Unpause the contract.  Convenience wrapper around [`save_pause_state`].
///
/// This does **not** perform any authorization check — callers are responsible
/// for verifying admin identity before invoking this helper.
pub fn unpause(env: &Env) {
    save_pause_state(env, false);
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    // ── require_not_paused ────────────────────────────────────────────────────

    #[test]
    fn require_not_paused_passes_when_not_paused() {
        let env = Env::default();
        save_pause_state(&env, false);
        assert!(require_not_paused(&env).is_ok());
    }

    #[test]
    fn require_not_paused_returns_error_when_paused() {
        let env = Env::default();
        save_pause_state(&env, true);
        assert_eq!(require_not_paused(&env), Err(Error::ContractPaused));
    }

    #[test]
    fn require_not_paused_passes_after_unpause() {
        let env = Env::default();
        save_pause_state(&env, true);
        save_pause_state(&env, false);
        assert!(require_not_paused(&env).is_ok());
    }

    // ── require_paused ────────────────────────────────────────────────────────

    #[test]
    fn require_paused_passes_when_paused() {
        let env = Env::default();
        save_pause_state(&env, true);
        assert!(require_paused(&env).is_ok());
    }

    #[test]
    fn require_paused_returns_not_paused_when_contract_is_active() {
        let env = Env::default();
        save_pause_state(&env, false);
        assert_eq!(require_paused(&env), Err(Error::NotPaused));
    }

    // ── check_emergency_allowed ───────────────────────────────────────────────

    #[test]
    fn emergency_op_allowed_while_paused() {
        let env = Env::default();
        save_pause_state(&env, true);
        let allowed = [OP_UNPAUSE];
        // OP_UNPAUSE is in the allow list — must pass even when paused.
        assert!(check_emergency_allowed(&env, OP_UNPAUSE, &allowed).is_ok());
    }

    #[test]
    fn emergency_op_blocked_when_not_in_allow_list_and_paused() {
        let env = Env::default();
        save_pause_state(&env, true);
        let allowed = [OP_UNPAUSE];
        // Operation 99 is not in the allow list and contract is paused.
        assert_eq!(
            check_emergency_allowed(&env, 99, &allowed),
            Err(Error::ContractPaused)
        );
    }

    #[test]
    fn emergency_op_passes_when_not_paused_regardless_of_list() {
        let env = Env::default();
        save_pause_state(&env, false);
        // Even an unknown op passes because the contract is not paused.
        assert!(check_emergency_allowed(&env, 99, &[]).is_ok());
    }

    #[test]
    fn multiple_emergency_ops_are_each_allowed() {
        let env = Env::default();
        save_pause_state(&env, true);
        let allowed = [OP_UNPAUSE, OP_ADMIN_OVERRIDE];
        assert!(check_emergency_allowed(&env, OP_UNPAUSE, &allowed).is_ok());
        assert!(check_emergency_allowed(&env, OP_ADMIN_OVERRIDE, &allowed).is_ok());
    }

    #[test]
    fn non_emergency_op_blocked_with_multiple_allowed_ops() {
        let env = Env::default();
        save_pause_state(&env, true);
        let allowed = [OP_UNPAUSE, OP_ADMIN_OVERRIDE];
        assert_eq!(
            check_emergency_allowed(&env, 42, &allowed),
            Err(Error::ContractPaused)
        );
    }

    // ── pause / unpause helpers ───────────────────────────────────────────────

    #[test]
    fn pause_sets_paused_state() {
        let env = Env::default();
        pause(&env);
        assert_eq!(require_not_paused(&env), Err(Error::ContractPaused));
    }

    #[test]
    fn unpause_clears_paused_state() {
        let env = Env::default();
        pause(&env);
        unpause(&env);
        assert!(require_not_paused(&env).is_ok());
    }
}
