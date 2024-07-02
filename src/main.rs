use std::{collections::{HashMap, HashSet}, net::SocketAddr, time::Duration};

use bip300301::{
    client::{GetRawTransactionClient, GetRawTransactionVerbose},
    MainClient as _,
};
use bitcoin_0_31::hashes::Hash;
use bitcoincore_zmq::Error as ZmqError;
use bitcoincore_zmq::Message as ZmqMessage;
use clap::Parser;
use futures::stream;
use futures::StreamExt;
use futures::{stream::FuturesUnordered, TryStreamExt};
use jsonrpsee::http_client::HttpClient;
use thiserror::Error;
use tracing_subscriber::{filter as tracing_filter, layer::SubscriberExt};

mod bitcoin_rpc;
mod bitcoin_script;

#[derive(Parser)]
struct Cli {
    /// Log level
    #[arg(default_value_t = tracing::Level::DEBUG, long)]
    log_level: tracing::Level,
    /// Bitcoin node RPC address
    #[arg(long)]
    rpc_addr: SocketAddr,
    /// Bitcoin node RPC pass
    #[arg(long)]
    rpc_pass: String,
    /// Bitcoin node RPC user
    #[arg(long)]
    rpc_user: String,
    /// Bitcoin node ZMQ endpoint for `rawblock`
    #[arg(long)]
    zmq_addr_rawblock: String,
}

// Configure loggers.
// If the file logger is set, returns a guard that must be held for the
// lifetime of the program in order to keep the file logger alive.
fn set_tracing_subscriber(log_level: tracing::Level) -> anyhow::Result<()> {
    let targets_filter = tracing_filter::Targets::new().with_default(log_level);
    let stdout_layer = tracing_subscriber::fmt::layer()
        .compact()
        .with_line_number(true);
    let tracing_subscriber = tracing_subscriber::registry()
        .with(targets_filter)
        .with(stdout_layer);
    tracing::subscriber::set_global_default(tracing_subscriber).map_err(|err| {
        let err = anyhow::Error::from(err);
        anyhow::anyhow!("setting default subscriber failed: {err:#}")
    })
}

fn subscribe_zmq(
    zmq_addr_rawblock: &str,
) -> Result<bitcoincore_zmq::MessageStream, bitcoincore_zmq::Error> {
    tracing::debug!("Attempting to subscribe to rawblock on `{zmq_addr_rawblock}`");
    bitcoincore_zmq::subscribe_async(&[zmq_addr_rawblock])
}

#[derive(Debug, Error)]
enum Error {
    #[error("Error deserializing tx")]
    BitcoinDeserialize(#[from] bitcoin::consensus::encode::FromHexError),
    #[error(transparent)]
    Rpc(#[from] jsonrpsee::core::ClientError),
    #[error(transparent)]
    Zmq(#[from] ZmqError),
    #[error("ZMQ stream ended unexpectedly")]
    ZmqStreamEnd,
}

async fn get_spent_outputs(
    rpc_client: &HttpClient,
    block: &bitcoin::Block,
) -> Result<HashMap<bitcoin::Txid, bitcoin::Transaction>, Error> {
    const MAX_CONCURRENT_REQUESTS: usize = 15;
    // txs needed to get spent outputs
    let txs_needed: HashSet<_> = block
        .txdata
        .iter()
        .filter(|tx| !tx.is_coinbase())
        .flat_map(|tx| tx.input.iter().map(|input| input.previous_output.txid))
        .collect();
    tracing::debug!("requesting {} raw txs...", txs_needed.len());
    let futs = txs_needed
        .into_iter()
        .map(|txid| async move {
            let txid_bytes: [u8; 32] = *txid.as_ref();
            let rpc_txid = bitcoin_0_31::Txid::from_byte_array(txid_bytes);
            tracing::debug!("getting raw tx for {txid}...");
            let tx_hex = rpc_client.get_raw_transaction(rpc_txid,
                GetRawTransactionVerbose::<false>,
                None
            ).await?;
            tracing::debug!("received raw tx for {txid}");
            let tx = bitcoin::consensus::encode::deserialize_hex(&tx_hex)?;
            Ok((txid, tx))
        });
    stream::iter(futs)
        .buffer_unordered(MAX_CONCURRENT_REQUESTS)
        .try_collect::<HashMap<_, _>>()
        .await
}

fn validate_tx(
    tx: &bitcoin::Transaction,
    spent_outputs: &HashMap<bitcoin::Txid, bitcoin::Transaction>,
) -> bool {
    let tx_encoded = bitcoin::consensus::serialize(tx);
    let get_spent_output = |outpoint: &bitcoin::OutPoint| {
        &spent_outputs[&outpoint.txid].output[outpoint.vout as usize]
    };
    for (idx, input) in tx.input.iter().enumerate() {
        let spent_output = get_spent_output(&input.previous_output);
        let spk_encoded = bitcoin::consensus::serialize(&spent_output.script_pubkey);
        if !bitcoin_script::verify(
            &spk_encoded,
            &tx_encoded,
            idx as u32,
            bitcoin_script::standard_script_verify_flags(),
            spent_output.value.to_sat() as i64,
        ) {
            return false;
        } else {
            continue;
        }
    }
    true
}

async fn validate_block(rpc_client: &HttpClient, block: &bitcoin::Block) -> Result<bool, Error> {
    tracing::debug!("getting spent outputs for {}...", block.block_hash());
    let spent_outputs = get_spent_outputs(rpc_client, block).await?;
    tracing::debug!("received spent outputs for {}...", block.block_hash());
    for tx in &block.txdata {
        if tx.is_coinbase() {
            continue;
        }
        if validate_tx(tx, &spent_outputs) {
            continue;
        } else {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn handle_zmq(
    mut zmq_rx: bitcoincore_zmq::MessageStream,
    rpc_client: HttpClient,
) -> Result<(), Error> {
    while let Some(zmq_msg) = zmq_rx.try_next().await? {
        match zmq_msg {
            ZmqMessage::Block(block, _seq) => {
                tracing::debug!("Validating block...");
                if !validate_block(&rpc_client, &block).await? {
                    let block_hash = block.block_hash();
                    tracing::warn!("Invalidating block {block_hash}");
                    let block_hash: [u8; 32] = *block_hash.as_ref();
                    let block_hash = bitcoin_0_31::BlockHash::from_byte_array(block_hash);
                    // FIXME: re-enable
                    //rpc_client.invalidate_block(block_hash).await?;
                }
            }
            ZmqMessage::HashBlock(..)
            | ZmqMessage::HashTx(..)
            | ZmqMessage::Sequence(..)
            | ZmqMessage::Tx(..) => (),
        }
    }
    Err(Error::ZmqStreamEnd)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    set_tracing_subscriber(cli.log_level)?;
    let rpc_client = {
        const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
        let client = bip300301::client(cli.rpc_addr, &cli.rpc_pass, Some(REQUEST_TIMEOUT), &cli.rpc_user)?;
        // get RPC version to check that RPC client is configured correctly
        let _network_info = client.get_network_info().await?;
        tracing::debug!("connected to RPC server");
        client
    };
    let zmq_rx = subscribe_zmq(&cli.zmq_addr_rawblock)?;
    tracing::debug!("subscribed to rawblock");
    let () = handle_zmq(zmq_rx, rpc_client).await?;
    Ok(())
}
