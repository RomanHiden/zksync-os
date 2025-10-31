use crate::run::{NextTxResponse, TxSource};
use std::collections::VecDeque;
use zksync_os_interface::traits::EncodedTx;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct TxListSource {
    pub transactions: VecDeque<Vec<u8>>,
}

impl TxSource for TxListSource {
    fn get_next_tx(&mut self) -> NextTxResponse {
        match self.transactions.pop_front() {
            Some(tx) => NextTxResponse::Tx(EncodedTx::Abi(tx)),
            None => NextTxResponse::SealBlock,
        }
    }
}
