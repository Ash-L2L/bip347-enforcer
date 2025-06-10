use std::{net::SocketAddr, time::Duration};

use bitcoin::ScriptBuf;
use bitcoin_jsonrpsee::{
    jsonrpsee::http_client::{HttpClient, HttpClientBuilder},
    MainClient as _,
};
use clap::Parser;
use futures::{channel::oneshot, FutureExt};
use thiserror::Error;
use tracing_subscriber::{filter as tracing_filter, layer::SubscriberExt};

mod bitcoin_script;
mod enforcer;

const DEFAULT_SERVE_RPC_ADDR: SocketAddr = SocketAddr::V4(
    std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 21_000),
);

#[derive(Debug, Error)]
enum ParseBitcoinAddressError {
    #[error("bitcoin address is not valid for signet")]
    NotSignet,
    #[error("invalid bitcoin address")]
    Parse(#[source] bitcoin::address::ParseError),
}

fn parse_bitcoin_address(
    s: &str,
) -> Result<bitcoin::Address, ParseBitcoinAddressError> {
    use std::str::FromStr;
    let unchecked = bitcoin::Address::from_str(s)
        .map_err(ParseBitcoinAddressError::Parse)?;
    let checked_addr = unchecked
        .require_network(bitcoin::Network::Signet)
        .map_err(|_| ParseBitcoinAddressError::NotSignet)?;
    Ok(checked_addr)
}

#[derive(Parser)]
struct Cli {
    /// Enable mempool / GBT server
    #[arg(long, default_value_t = false)]
    enable_mempool: bool,
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
    /// Serve `getblocktemplate` RPC from this address
    #[arg(default_value_t = DEFAULT_SERVE_RPC_ADDR, long)]
    serve_rpc_addr: SocketAddr,
    /// Address for block reward payment on signets
    #[arg(long = "signet-coinbase-recipient", value_parser = parse_bitcoin_address)]
    signet_coinbase_recipient: Option<bitcoin::Address>,
    /// Bitcoin node ZMQ endpoint for `sequence`
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

#[derive(Debug, Error)]
enum Error {
    #[error("Error creating mempool server")]
    CreateServer(#[from] cusf_enforcer_mempool::server::CreateServerError),
    #[error("Initial mempool sync error")]
    InitMempoolSync(
        #[from]
        cusf_enforcer_mempool::mempool::InitialSyncMempoolError<
            enforcer::Bip347Enforcer,
        >,
    ),
    #[error(transparent)]
    Rpc(#[from] bitcoin_jsonrpsee::jsonrpsee::core::ClientError),
    #[error("Build mempool RPC server error")]
    RpcServer(#[source] std::io::Error),
    #[error(transparent)]
    ZmqSubscribe(#[from] cusf_enforcer_mempool::zmq::SubscribeSequenceError),
}

async fn block_enforcer(
    zmq_addr_sequence: &str,
    rpc_client: HttpClient,
) -> Result<
    (),
    cusf_enforcer_mempool::cusf_enforcer::TaskError<enforcer::Bip347Enforcer>,
> {
    let mut enforcer = enforcer::Bip347Enforcer {
        rpc_client: rpc_client.clone(),
    };
    cusf_enforcer_mempool::cusf_enforcer::task(
        &mut enforcer,
        &rpc_client,
        zmq_addr_sequence,
        futures::future::pending(),
    )
    .await
}

async fn spawn_rpc_server(
    server: cusf_enforcer_mempool::server::Server<enforcer::Bip347Enforcer>,
    serve_rpc_addr: SocketAddr,
) -> std::io::Result<jsonrpsee::server::ServerHandle> {
    use cusf_enforcer_mempool::server::RpcServer;
    let handle = jsonrpsee::server::Server::builder()
        .build(serve_rpc_addr)
        .await?
        .start(server.into_rpc());
    Ok(handle)
}

async fn mempool_enforcer(
    serve_rpc_addr: SocketAddr,
    zmq_addr_sequence: &str,
    rpc_client: HttpClient,
    network_info: bitcoin_jsonrpsee::client::NetworkInfo,
    coinbase_spk: ScriptBuf,
) -> Result<(), Error> {
    use futures::future::{select, Either};
    let chain_info = rpc_client.get_blockchain_info().await?;
    let sample_block_template =
        rpc_client.get_block_template(Default::default()).await?;
    let mut enforcer = enforcer::Bip347Enforcer {
        rpc_client: rpc_client.clone(),
    };
    let (sequence_stream, mempool, tx_cache) = {
        cusf_enforcer_mempool::mempool::init_sync_mempool(
            &mut enforcer,
            &rpc_client,
            zmq_addr_sequence,
            futures::future::pending(),
        )
        .await?
    };
    tracing::info!("Initial mempool sync complete");
    let (enforcer_stopped_tx, enforcer_stopped_rx) = oneshot::channel();
    let mempool = cusf_enforcer_mempool::mempool::MempoolSync::new(
        enforcer,
        mempool,
        tx_cache,
        rpc_client,
        sequence_stream,
        |err| async {
            let err = anyhow::Error::from(err);
            tracing::error!("{err:#}");
            if let Err(()) = enforcer_stopped_tx.send(()) {
                tracing::error!("Failed to send shutdown signal");
            };
        },
    );
    let server = cusf_enforcer_mempool::server::Server::new(
        coinbase_spk,
        mempool,
        chain_info.chain,
        network_info,
        sample_block_template,
    )?;
    let rpc_server_handle = spawn_rpc_server(server, serve_rpc_addr)
        .await
        .map_err(Error::RpcServer)?;

    match select(enforcer_stopped_rx, rpc_server_handle.stopped().boxed()).await
    {
        Either::Left((Ok(()), _)) | Either::Right(((), _)) => (),
        Either::Left((Err(oneshot::Canceled), _)) => {
            tracing::error!("Shutdown signal channel closed");
        }
    };
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    set_tracing_subscriber(cli.log_level)?;
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
    if cli.enable_mempool {
        // A mempool of default size might contain >300k txs.
        // batch Requesting 300k txs requires ~30MiB,
        // so 100MiB should be enough
        const MAX_REQUEST_SIZE: u32 = 100 * (1 << 20);
        // Default mempool size is 300MB, so 1GiB should be enough
        const MAX_RESPONSE_SIZE: u32 = 1 << 30;
        let (rpc_client, network_info) = {
            let client_builder = HttpClientBuilder::new()
                .max_request_size(MAX_REQUEST_SIZE)
                .max_response_size(MAX_RESPONSE_SIZE)
                .request_timeout(REQUEST_TIMEOUT);
            let client = bitcoin_jsonrpsee::client(
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
        let mining_reward_address = cli
            .signet_coinbase_recipient
            .map(|addr| addr.script_pubkey())
            .unwrap_or_default();
        mempool_enforcer(
            cli.serve_rpc_addr,
            &cli.zmq_addr_sequence,
            rpc_client,
            network_info,
            mining_reward_address,
        )
        .await?;
    } else {
        let (rpc_client, _network_info) = {
            let client_builder =
                HttpClientBuilder::new().request_timeout(REQUEST_TIMEOUT);
            let client = bitcoin_jsonrpsee::client(
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
        let () = block_enforcer(&cli.zmq_addr_sequence, rpc_client).await?;
    }
    Ok(())
}
