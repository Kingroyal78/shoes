//! Local outbound routing for the V2Board node backend.
//!
//! See `docs/v2board-routing-plan.md`. Outbounds and rules live in the local
//! config file only; the V2Board contract is untouched.

pub mod compiler;
pub mod dispatcher;
pub mod index;
pub mod rules;
