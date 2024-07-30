use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    net::SocketAddr,
    time::Duration,
};

use bip300301::{
    client::{GetRawTransactionClient, GetRawTransactionVerbose},
    MainClient as _,
};
use bitcoin::Block;
use bitcoin_0_31::hashes::Hash;
use bitcoin_script::{op_cat_verify_flag, verify_tx, VerifyTxError};
use clap::Parser;
use futures::{
    stream::{self, BoxStream},
    StreamExt, TryStream, TryStreamExt,
};
use jsonrpsee::http_client::HttpClient;
use thiserror::Error;
use tracing_subscriber::{filter as tracing_filter, layer::SubscriberExt};
use zeromq::{Socket, SocketRecv, ZmqError, ZmqMessage};

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

// Configure logger.
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

struct RawBlockMessage {
    block: Block,
    seq: u32,
}

#[derive(Debug, Error)]
enum DeserializeRawBlockMessageError {
    #[error("Failed to deserialize block")]
    DeserializeBlock(#[from] bitcoin::consensus::encode::Error),
    #[error("Failed to deserialize sequence")]
    DeserializeSeq(#[source] <[u8; 4] as TryFrom<&'static [u8]>>::Error),
    #[error("Missing block (second frame)")]
    MissingBlock,
    #[error(r#"Missing prefix; first frame must be `b"rawblock"`"#)]
    MissingPrefix,
    #[error("Missing sequence (third frame)")]
    MissingSeq,
    #[error(r#"Wrong prefix; first frame must be `b"rawblock"`"#)]
    WrongPrefix,
}

impl TryFrom<ZmqMessage> for RawBlockMessage {
    type Error = DeserializeRawBlockMessageError;

    fn try_from(msg: ZmqMessage) -> Result<Self, Self::Error> {
        let mut msg = msg.into_vecdeque();
        let Some(prefix) = msg.pop_front() else {
            return Err(Self::Error::MissingPrefix);
        };
        if *prefix != *b"rawblock" {
            return Err(Self::Error::WrongPrefix);
        };
        let Some(block) = msg.pop_front() else {
            return Err(Self::Error::MissingBlock);
        };
        let block = bitcoin::consensus::deserialize(&block)?;
        let Some(seq_bytes) = msg.pop_front() else {
            return Err(Self::Error::MissingSeq);
        };
        let seq = u32::from_le_bytes(
            (*seq_bytes)
                .try_into()
                .map_err(Self::Error::DeserializeSeq)?,
        );
        Ok(Self { block, seq })
    }
}

#[derive(Debug, Error)]
enum RawBlockStreamError {
    #[error("Error deserializing message")]
    Deserialize(#[from] DeserializeRawBlockMessageError),
    #[error("Missing message with sequence {0}")]
    MissingMessage(u32),
    #[error("ZMQ error")]
    Zmq(#[from] ZmqError),
}

#[tracing::instrument]
async fn subscribe_zmq_native(
    zmq_addr_rawblock: &str,
) -> Result<BoxStream<Result<Block, RawBlockStreamError>>, ZmqError> {
    tracing::debug!("Attempting to connect to ZMQ server...");
    let mut socket = zeromq::SubSocket::new();
    socket.connect(zmq_addr_rawblock).await?;
    tracing::info!("Connected to ZMQ server");
    tracing::debug!("Attempting to subscribe to `rawblock` topic...");
    socket.subscribe("rawblock").await?;
    tracing::info!("Subscribed to `rawblock`");
    let res = stream::try_unfold(socket, |mut socket| async {
        let msg: RawBlockMessage = socket.recv().await?.try_into()?;
        Ok(Some((msg, socket)))
    })
    .try_filter_map({
        let mut next_seq: Option<u32> = None;
        move |raw_block_msg| {
            let res = match next_seq {
                None => {
                    next_seq = Some(raw_block_msg.seq + 1);
                    Ok(Some(raw_block_msg.block))
                }
                Some(ref mut next_seq) => {
                    match raw_block_msg.seq.cmp(next_seq) {
                        Ordering::Less => Ok(None),
                        Ordering::Equal => {
                            *next_seq = raw_block_msg.seq + 1;
                            Ok(Some(raw_block_msg.block))
                        }
                        Ordering::Greater => {
                            Err(RawBlockStreamError::MissingMessage(*next_seq))
                        }
                    }
                }
            };
            async { res }
        }
    })
    .boxed();
    Ok(res)
}

#[derive(Debug, Error)]
enum Error {
    #[error("Error deserializing tx")]
    BitcoinDeserialize(#[from] bitcoin::consensus::encode::FromHexError),
    #[error(transparent)]
    RawBlockStream(#[from] RawBlockStreamError),
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
    let futs = txs_needed.into_iter().map(|txid| async move {
        let txid_bytes: [u8; 32] = *txid.as_ref();
        let rpc_txid = bitcoin_0_31::Txid::from_byte_array(txid_bytes);
        tracing::debug!("getting raw tx for {txid}...");
        let tx_hex = rpc_client
            .get_raw_transaction(
                rpc_txid,
                GetRawTransactionVerbose::<false>,
                None,
            )
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
pub struct VerifyBlockError {
    pub tx_idx: usize,
    #[source]
    pub source: VerifyTxError,
}

async fn validate_block(
    rpc_client: &HttpClient,
    block: &bitcoin::Block,
) -> Result<Result<(), VerifyBlockError>, Error> {
    tracing::debug!("getting spent outputs for {}...", block.block_hash());
    let spent_outputs = get_spent_outputs(rpc_client, block).await?;
    tracing::debug!("received spent outputs for {}...", block.block_hash());
    for (tx_idx, tx) in block.txdata.iter().enumerate() {
        if tx.is_coinbase() {
            continue;
        }
        if let Err(err) = verify_tx(tx, &spent_outputs, op_cat_verify_flag()) {
            return Ok(Err(VerifyBlockError {
                tx_idx,
                source: err,
            }));
        } else {
            continue;
        };
    }
    Ok(Ok(()))
}

async fn handle_raw_blocks<RawBlockStream>(
    mut raw_blocks: RawBlockStream,
    rpc_client: HttpClient,
) -> Result<(), Error>
where
    RawBlockStream: TryStream<Ok = Block, Error = RawBlockStreamError> + Unpin,
{
    while let Some(block) = raw_blocks.try_next().await? {
        let block_hash = block.block_hash();
        tracing::debug!("Validating block {block_hash}...");
        if let Err(err) = validate_block(&rpc_client, &block).await? {
            let err = anyhow::Error::from(err);
            tracing::warn!("Invalidating block {block_hash}: {err:#}");
            let block_hash: [u8; 32] = *block_hash.as_ref();
            let block_hash =
                bitcoin_0_31::BlockHash::from_byte_array(block_hash);
            rpc_client.invalidate_block(block_hash).await?;
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
        let client = bip300301::client(
            cli.rpc_addr,
            &cli.rpc_pass,
            Some(REQUEST_TIMEOUT),
            &cli.rpc_user,
        )?;
        // get network info to check that RPC client is configured correctly
        let _network_info = client.get_network_info().await?;
        tracing::debug!("connected to RPC server");
        client
    };
    //let zmq_rx = subscribe_zmq(&cli.zmq_addr_rawblock)?;
    //tracing::debug!("subscribed to rawblock");
    let raw_blocks = subscribe_zmq_native(&cli.zmq_addr_rawblock).await?;
    //let () = handle_zmq(zmq_rx, rpc_client).await?;
    let () = handle_raw_blocks(raw_blocks, rpc_client).await?;
    Ok(())
}
