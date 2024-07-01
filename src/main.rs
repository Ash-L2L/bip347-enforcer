use std::collections::{HashMap, HashSet};

use bitcoincore_rpc_async::{Auth as RpcAuth, Client as RpcClient, Error as RpcError, RpcApi};
use bitcoincore_zmq::Error as ZmqError;
use bitcoincore_zmq::Message as ZmqMessage;
use clap::Parser;
use futures::{stream::FuturesUnordered, TryStreamExt};
use sapio_bitcoin::hashes::Hash;
use thiserror::Error;
use tracing_subscriber::{filter as tracing_filter, layer::SubscriberExt};

mod bitcoin_script;

#[derive(Parser)]
struct Cli {
    /// Log level
    #[arg(default_value_t = tracing::Level::DEBUG, long)]
    log_level: tracing::Level,
    /// Bitcoin node RPC address
    #[arg(long)]
    rpc_addr: String,
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
    Rpc(#[from] RpcError),
    #[error(transparent)]
    Zmq(#[from] ZmqError),
    #[error("ZMQ stream ended unexpectedly")]
    ZmqStreamEnd,
}

async fn get_spent_outputs(
    rpc_client: &RpcClient,
    block: &bitcoin::Block,
) -> Result<HashMap<bitcoin::Txid, bitcoin::Transaction>, Error> {
    // txs needed to get spent outputs
    let txs_needed: HashSet<_> = block
        .txdata
        .iter()
        .flat_map(|tx| tx.input.iter().map(|input| input.previous_output.txid))
        .collect();
    txs_needed
        .into_iter()
        .map(|txid| async move {
            let txid_bytes: [u8; 32] = *txid.as_ref();
            let rpc_txid = sapio_bitcoin::Txid::from_inner(txid_bytes);
            let tx_hex = rpc_client.get_raw_transaction_hex(&rpc_txid, None).await?;
            let tx = bitcoin::consensus::encode::deserialize_hex(&tx_hex)?;
            Ok((txid, tx))
        })
        .collect::<FuturesUnordered<_>>()
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

async fn validate_block(rpc_client: &RpcClient, block: &bitcoin::Block) -> Result<bool, Error> {
    let spent_outputs = get_spent_outputs(rpc_client, block).await?;
    for tx in &block.txdata {
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
    rpc_client: RpcClient,
) -> Result<(), Error> {
    while let Some(zmq_msg) = zmq_rx.try_next().await? {
        match zmq_msg {
            ZmqMessage::Block(block, _seq) => {
                if !validate_block(&rpc_client, &block).await? {
                    let block_hash: [u8; 32] = *block.block_hash().as_ref();
                    let block_hash = sapio_bitcoin::hash_types::BlockHash::from_inner(block_hash);
                    rpc_client.invalidate_block(&block_hash).await?;
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
        let auth = RpcAuth::UserPass(cli.rpc_user, cli.rpc_pass);
        let client = RpcClient::new(cli.rpc_addr, auth).await?;
        // get RPC version to check that RPC client is configured correctly
        let _version: usize = client.version().await?;
        client
    };
    let zmq_rx = subscribe_zmq(&cli.zmq_addr_rawblock)?;
    let () = handle_zmq(zmq_rx, rpc_client).await?;
    Ok(())
}
