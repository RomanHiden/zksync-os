use ruint::aliases::B160;

// zk_ee/src/system/validator/mod.rs
use crate::system::{CallResult, ExecutionEnvironmentLaunchParams, SystemTypes};

#[derive(Debug)]
pub enum TxValidationError {
    FilteredByValidator,
}

pub type TxValidationResult = Result<(), TxValidationError>;

/// High–level per–tx validator, used by bootloader / run_prepared.
pub trait TxValidator<S: SystemTypes> {
    /// Called before bootloader / system starts processing a tx.
    fn begin_tx(&mut self, _calldata: &[u8]) -> TxValidationResult {
        Ok(())
    }

    /// Called after tx is fully processed (success or revert).
    fn finish_tx(&mut self) -> TxValidationResult {
        Ok(())
    }
}

/// No-op validator (mirrors `NopTracer`).
#[derive(Default)]
pub struct NopTxValidator;

impl<S: SystemTypes> TxValidator<S> for NopTxValidator {}
