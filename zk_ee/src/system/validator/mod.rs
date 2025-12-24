use crate::system::SystemTypes;

#[derive(Debug)]
pub enum TxValidationError {
    FilteredByValidator,
}

pub type TxValidationResult = Result<(), TxValidationError>;

pub trait TxValidator<S: SystemTypes> {
    fn begin_tx(&mut self, calldata: &[u8]) -> TxValidationResult;

    fn finish_tx(&mut self) -> TxValidationResult;
}

#[derive(Default)]
pub struct NopTxValidator;

impl<S: SystemTypes> TxValidator<S> for NopTxValidator {
    fn begin_tx(&mut self, _calldata: &[u8]) -> TxValidationResult {
        Ok(())
    }

    fn finish_tx(&mut self) -> TxValidationResult {
        Ok(())
    }
}
