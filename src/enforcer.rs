use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    convert::Infallible,
    future::Future,
};

use bitcoin::{BlockHash, Transaction, Txid};
use bitcoin_jsonrpsee::{
    client::{GetRawTransactionClient, GetRawTransactionVerbose},
    jsonrpsee::http_client::HttpClient,
};
use cusf_enforcer_mempool::{
    cusf_block_producer::{
        typewit, CoinbaseTxn, CusfBlockProducer, InitialBlockTemplate,
    },
    cusf_enforcer::{ConnectBlockAction, CusfEnforcer},
};
use futures::{stream, StreamExt as _, TryStreamExt as _};
use thiserror::Error;

use crate::bitcoin_script::{op_cat_verify_flag, verify_tx, VerifyTxError};

#[derive(Debug, Error)]
pub enum ConnectBlockError {
    #[error("Error deserializing tx")]
    BitcoinDeserialize(#[from] bitcoin::consensus::encode::FromHexError),
    #[error(transparent)]
    Rpc(#[from] bitcoin_jsonrpsee::jsonrpsee::core::ClientError),
}

async fn get_spent_outputs(
    rpc_client: &HttpClient,
    block: &bitcoin::Block,
) -> Result<HashMap<bitcoin::Txid, bitcoin::Transaction>, ConnectBlockError> {
    const MAX_CONCURRENT_REQUESTS: usize = 15;
    // txs needed to get spent outputs
    let txs_needed: HashSet<_> = block
        .txdata
        .iter()
        .filter(|tx| !tx.is_coinbase())
        .flat_map(|tx| tx.input.iter().map(|input| input.previous_output.txid))
        .collect();
    tracing::debug!("requesting {} raw txs...", txs_needed.len());
    let futs = txs_needed.into_iter().map(|txid| async move {
        tracing::debug!("getting raw tx for {txid}...");
        let tx_hex = rpc_client
            .get_raw_transaction(txid, GetRawTransactionVerbose::<false>, None)
            .await?;
        tracing::debug!("received raw tx for {txid}");
        let tx = bitcoin::consensus::encode::deserialize_hex(&tx_hex)?;
        Ok((txid, tx))
    });
    stream::iter(futs)
        .buffer_unordered(MAX_CONCURRENT_REQUESTS)
        .try_collect::<HashMap<_, _>>()
        .await
}

#[derive(Debug, Error)]
#[error("Error verifying tx {tx_idx}")]
struct VerifyBlockError {
    tx_idx: usize,
    #[source]
    source: VerifyTxError,
}

#[derive(Debug)]
pub struct Bip347Enforcer {
    pub rpc_client: HttpClient,
}

impl CusfEnforcer for Bip347Enforcer {
    type SyncError = Infallible;

    async fn sync_to_tip<Signal: Future<Output = ()> + Send>(
        &mut self,
        _shutdown_signal: Signal,
        _tip: BlockHash,
    ) -> Result<(), Self::SyncError> {
        Ok(())
    }

    type ConnectBlockError = ConnectBlockError;

    async fn connect_block(
        &mut self,
        block: &bitcoin::Block,
    ) -> Result<ConnectBlockAction, Self::ConnectBlockError> {
        let block_hash = block.block_hash();
        tracing::debug!("getting spent outputs for {block_hash}...");
        let spent_outputs = get_spent_outputs(&self.rpc_client, block).await?;
        tracing::debug!("received spent outputs for {block_hash}...");
        for (tx_idx, tx) in block.txdata.iter().enumerate() {
            if tx.is_coinbase() {
                continue;
            }
            match verify_tx(tx, &spent_outputs, op_cat_verify_flag()) {
                Ok(()) => (),
                Err(err) => {
                    let err = VerifyBlockError {
                        tx_idx,
                        source: err,
                    };
                    tracing::warn!(%block_hash, "{err:#}");
                    return Ok(ConnectBlockAction::Reject);
                }
            }
        }
        Ok(ConnectBlockAction::Accept {
            remove_mempool_txs: Default::default(),
        })
    }

    type DisconnectBlockError = Infallible;

    async fn disconnect_block(
        &mut self,
        _block_hash: BlockHash,
    ) -> Result<(), Self::DisconnectBlockError> {
        Ok(())
    }

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

impl CusfBlockProducer for Bip347Enforcer {
    type InitialBlockTemplateError = Infallible;

    async fn initial_block_template<const COINBASE_TXN: bool>(
        &self,
        _coinbase_txn_wit: typewit::const_marker::BoolWit<COINBASE_TXN>,
        _template: InitialBlockTemplate<COINBASE_TXN>,
    ) -> Result<
        InitialBlockTemplate<COINBASE_TXN>,
        Self::InitialBlockTemplateError,
    >
    where
        typewit::const_marker::Bool<COINBASE_TXN>: CoinbaseTxn,
    {
        Ok(InitialBlockTemplate {
            coinbase_txouts: <typewit::const_marker::Bool<COINBASE_TXN> as CoinbaseTxn>::CoinbaseTxouts::default(),
            prefix_txs: Vec::new(),
            exclude_mempool_txs: HashSet::new(),
        })
    }

    type SuffixTxsError = Infallible;

    async fn suffix_txs<const COINBASE_TXN: bool>(
        &self,
        _coinbase_txn_wit: typewit::const_marker::BoolWit<COINBASE_TXN>,
        _template: &InitialBlockTemplate<COINBASE_TXN>,
    ) -> Result<Vec<(Transaction, bitcoin::Amount)>, Self::SuffixTxsError>
    where
        typewit::const_marker::Bool<COINBASE_TXN>: CoinbaseTxn,
    {
        Ok(Vec::new())
    }
}
