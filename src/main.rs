use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    net::SocketAddr,
    time::Duration,
};

use bip300301::{
    client::{GetRawTransactionClient, GetRawTransactionVerbose},
    jsonrpsee::http_client::{HttpClient, HttpClientBuilder},
    MainClient as _,
};
use bitcoin::Block;
use bitcoin_script::{op_cat_verify_flag, verify_tx, VerifyTxError};
use cfg_if::cfg_if;
use clap::Parser;
use futures::{
    stream::{self, BoxStream},
    StreamExt, TryStream, TryStreamExt,
};
use thiserror::Error;
use tracing_subscriber::{filter as tracing_filter, layer::SubscriberExt};
use zeromq::{Socket, SocketRecv, ZmqError, ZmqMessage};

mod bitcoin_script;
#[cfg(feature = "mempool")]
mod enforcer;

#[cfg(feature = "mempool")]
const DEFAULT_SERVE_RPC_ADDR: SocketAddr = SocketAddr::V4(
    std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 21_000),
);

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
    #[cfg(feature = "mempool")]
    /// Serve `getblocktemplate` RPC from this address
    #[arg(default_value_t = DEFAULT_SERVE_RPC_ADDR, long)]
    serve_rpc_addr: SocketAddr,
    /// Bitcoin node ZMQ endpoint for `rawblock`
    #[arg(long)]
    zmq_addr_rawblock: String,
    /// Bitcoin node ZMQ endpoint for `sequence`
    #[cfg(feature = "mempool")]
    #[arg(long)]
    zmq_addr_sequence: String,
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
    #[cfg(feature = "mempool")]
    #[error("Initial mempool sync error")]
    InitMempoolSync(
        #[from] cusf_enforcer_mempool::mempool::InitialSyncMempoolError,
    ),
    #[error(transparent)]
    RawBlockStream(#[from] RawBlockStreamError),
    #[error(transparent)]
    Rpc(#[from] bip300301::jsonrpsee::core::ClientError),
    #[cfg(feature = "mempool")]
    #[error("Build mempool RPC server error")]
    RpcServer(#[source] std::io::Error),
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
            rpc_client.invalidate_block(block_hash).await?;
        }
    }
    Err(Error::ZmqStreamEnd)
}

async fn block_enforcer(
    zmq_addr_rawblock: &str,
    rpc_client: HttpClient,
) -> Result<(), Error> {
    let raw_blocks = subscribe_zmq_native(zmq_addr_rawblock).await?;
    handle_raw_blocks(raw_blocks, rpc_client).await
}

#[cfg(feature = "mempool")]
async fn spawn_rpc_server(
    server: cusf_enforcer_mempool::server::Server,
    serve_rpc_addr: SocketAddr,
) -> std::io::Result<jsonrpsee::server::ServerHandle> {
    use cusf_enforcer_mempool::server::RpcServer;
    let handle = jsonrpsee::server::Server::builder()
        .build(serve_rpc_addr)
        .await?
        .start(server.into_rpc());
    Ok(handle)
}

#[cfg(feature = "mempool")]
async fn mempool_enforcer(
    serve_rpc_addr: SocketAddr,
    zmq_addr_sequence: &str,
    rpc_client: HttpClient,
    network_info: bip300301::client::NetworkInfo,
) -> Result<(), Error> {
    let sample_block_template =
        rpc_client.get_block_template(Default::default()).await?;
    let mut sequence_stream =
        cusf_enforcer_mempool::zmq::subscribe_sequence(zmq_addr_sequence)
            .await?;
    let (mempool, tx_cache) = {
        cusf_enforcer_mempool::mempool::init_sync_mempool(
            &rpc_client,
            &mut sequence_stream,
            sample_block_template.prev_blockhash,
        )
        .await?
    };
    tracing::info!("Initial mempool sync complete");
    let mempool = cusf_enforcer_mempool::mempool::MempoolSync::new(
        enforcer::Bip347Enforcer,
        mempool,
        tx_cache,
        &rpc_client,
        sequence_stream,
    );
    let server = cusf_enforcer_mempool::server::Server::new(
        mempool,
        network_info,
        sample_block_template,
    );
    let rpc_server_handle = spawn_rpc_server(server, serve_rpc_addr)
        .await
        .map_err(Error::RpcServer)?;
    let () = rpc_server_handle.stopped().await;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    set_tracing_subscriber(cli.log_level)?;
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
    cfg_if! {
        if #[cfg(feature = "mempool")] {
            // A mempool of default size might contain >300k txs.
            // batch Requesting 300k txs requires ~30MiB,
            // so 100MiB should be enough
            const MAX_REQUEST_SIZE: u32 = 100 * (1 << 20);
            // Default mempool size is 300MB, so 1GiB should be enough
            const MAX_RESPONSE_SIZE: u32 = 1 << 30;
            let (rpc_client, network_info) = {
                let client_builder =
                    HttpClientBuilder::new()
                        .max_request_size(MAX_REQUEST_SIZE)
                        .max_response_size(MAX_RESPONSE_SIZE)
                        .request_timeout(REQUEST_TIMEOUT);
                let client = bip300301::client(
                    cli.rpc_addr,
                    Some(client_builder),
                    &cli.rpc_pass,
                    &cli.rpc_user,
                )?;
                // get network info to check that RPC client is configured correctly
                let network_info = client.get_network_info().await?;
                tracing::debug!("connected to RPC server");
                (client, network_info)
            };
            let ((), ()) = futures::future::try_join(
                block_enforcer(&cli.zmq_addr_rawblock, rpc_client.clone()),
                mempool_enforcer(cli.serve_rpc_addr, &cli.zmq_addr_sequence, rpc_client, network_info)
            ).await?;
        } else {
            let (rpc_client, _network_info) = {
                let client_builder =
                    HttpClientBuilder::new()
                        .request_timeout(REQUEST_TIMEOUT);
                let client = bip300301::client(
                    cli.rpc_addr,
                    Some(client_builder),
                    &cli.rpc_pass,
                    &cli.rpc_user,
                )?;
                // get network info to check that RPC client is configured correctly
                let network_info = client.get_network_info().await?;
                tracing::debug!("connected to RPC server");
                (client, network_info)
            };
            let () = block_enforcer(&cli.zmq_addr_rawblock, rpc_client).await?;
        }
    }
    Ok(())
}
