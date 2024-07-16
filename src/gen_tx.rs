use std::str::FromStr;

use bitcoin::{
    absolute::LockTime,
    address::NetworkUnchecked,
    amount::ParseAmountError,
    hex::{DisplayHex, FromHex},
    key::Secp256k1,
    opcodes::all::{OP_CAT, OP_EQUAL},
    secp256k1::rand::rngs::OsRng,
    taproot::{ControlBlock, LeafVersion, TaprootBuilder, TaprootError},
    transaction::Version,
    Address, Amount, Denomination, OutPoint, PublicKey, ScriptBuf, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use thiserror::Error;

#[derive(Clone, Debug)]
struct ControlBlockArg(ControlBlock);

#[derive(Debug, Error)]
enum ParseControlBlockError {
    #[error(transparent)]
    FromHex(<Vec<u8> as FromHex>::Error),
    #[error(transparent)]
    Taproot(TaprootError),
}

impl FromStr for ControlBlockArg {
    type Err = ParseControlBlockError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = Vec::<u8>::from_hex(s).map_err(Self::Err::FromHex)?;
        let control_block =
            ControlBlock::decode(&bytes).map_err(Self::Err::Taproot)?;
        Ok(Self(control_block))
    }
}

#[derive(Clone, Debug)]
struct AmountBtcArg(Amount);

impl FromStr for AmountBtcArg {
    type Err = ParseAmountError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Amount::from_str_in(s, Denomination::Bitcoin).map(Self)
    }
}

#[derive(Clone, Debug)]
struct HexString(Vec<u8>);

impl FromStr for HexString {
    type Err = <Vec<u8> as FromHex>::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Vec::<u8>::from_hex(s).map(Self)
    }
}

#[derive(Args, Clone, Debug)]
#[group(multiple = false, required = true)]
struct OutputValueArg {
    /// Output value in Bitcoins
    #[arg(long)]
    output_value_btc: Option<AmountBtcArg>,
    /// Output value in Sats
    #[arg(long)]
    output_value_sats: Option<u64>,
}

impl OutputValueArg {
    fn value(&self) -> Option<Amount> {
        if let Some(output_value_btc) = &self.output_value_btc {
            Some(output_value_btc.0)
        } else {
            self.output_value_sats.map(Amount::from_sat)
        }
    }
}

#[derive(Parser)]
struct SpendArgs {
    /// Control block as a hex string
    #[arg(long, required(true))]
    control_block: ControlBlockArg,
    /// TxID for the input that should be spent
    #[arg(long)]
    input_txid: Txid,
    /// Output index for the input that should be spent
    #[arg(long)]
    input_vout: u32,
    /// Output address
    #[arg(long)]
    output_address: Address<NetworkUnchecked>,
    #[command(flatten)]
    output_value: OutputValueArg,
    /// Additional witness data, to be added before the script and control
    /// block.
    witness_data: Vec<HexString>,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a p2tr address and control block to use when spending
    P2trAddress,
    /// Spend a previously generated p2tr output
    Spend(Box<SpendArgs>),
}

#[derive(Clone, ValueEnum)]
enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl From<Network> for bitcoin::Network {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => bitcoin::Network::Bitcoin,
            Network::Testnet => bitcoin::Network::Testnet,
            Network::Regtest => bitcoin::Network::Regtest,
        }
    }
}

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[arg(global(true), long, value_enum, default_value_t = Network::Regtest)]
    network: Network,
}

fn script() -> ScriptBuf {
    ScriptBuf::builder()
        .push_opcode(OP_CAT)
        .push_opcode(OP_EQUAL)
        .into_script()
}

fn p2tr_address(network: bitcoin::Network) {
    let secp = Secp256k1::new();
    let (_sk, pk) = secp.generate_keypair(&mut OsRng);
    let pk: PublicKey = pk.into();
    let tr_spend_info = TaprootBuilder::new()
        .add_leaf(0, script())
        .unwrap()
        .finalize(&secp, pk.into())
        .unwrap();
    let address = Address::p2tr_tweaked(tr_spend_info.output_key(), network);
    let control_block = tr_spend_info
        .control_block(&(script(), LeafVersion::TapScript))
        .unwrap();
    println!("Address: {address}");
    println!("Control Block: {}", control_block.serialize().as_hex());
}

fn spend(
    network: bitcoin::Network,
    spend_args: SpendArgs,
) -> anyhow::Result<()> {
    let previous_output = OutPoint {
        txid: spend_args.input_txid,
        vout: spend_args.input_vout,
    };
    let mut witness = Witness::new();
    spend_args.witness_data.iter().for_each(|item| {
        witness.push(item.0.clone());
    });
    witness.push(script());
    witness.push(spend_args.control_block.0.serialize());
    let txin = TxIn {
        previous_output,
        witness,
        ..Default::default()
    };
    let address = spend_args.output_address.clone().require_network(network)?;
    let txout = TxOut {
        value: spend_args.output_value.value().unwrap(),
        script_pubkey: address.script_pubkey(),
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(1).unwrap(),
        input: vec![txin],
        output: vec![txout],
    };
    let tx_json = serde_json::to_string_pretty(&tx).unwrap();
    let raw_tx_hex = bitcoin::consensus::serialize(&tx).to_lower_hex_string();
    println!("{tx_json}");
    println!("RAW TX: {raw_tx_hex}");
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::P2trAddress => p2tr_address(cli.network.into()),
        Command::Spend(spend_args) => spend(cli.network.into(), *spend_args)?,
    }
    Ok(())
}
