use std::{borrow::Borrow, collections::HashMap, convert::Infallible};

use bitcoin::{Transaction, Txid};
use cusf_enforcer_mempool::cusf_enforcer::CusfEnforcer;

use crate::bitcoin_script::{op_cat_verify_flag, verify_tx};

#[derive(Debug, Default)]
pub struct Bip347Enforcer;

impl CusfEnforcer for Bip347Enforcer {
    type AcceptTxError = Infallible;

    fn accept_tx<TxRef>(
        &mut self,
        tx: &bitcoin::Transaction,
        tx_inputs: &HashMap<Txid, TxRef>,
    ) -> Result<bool, Self::AcceptTxError>
    where
        TxRef: Borrow<Transaction>,
    {
        let res = verify_tx(tx, tx_inputs, op_cat_verify_flag()).is_ok();
        Ok(res)
    }
}
