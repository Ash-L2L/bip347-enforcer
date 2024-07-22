use std::{
    cmp::Ordering,
    collections::VecDeque,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    str::FromStr,
    time::{Duration, SystemTime},
};

use bip300301::{client::BlockTemplate, MainClient as _};
use bitcoin::{
    absolute::LockTime,
    address::NetworkUnchecked,
    amount::ParseAmountError,
    block::Header,
    constants::{COINBASE_MATURITY, SUBSIDY_HALVING_INTERVAL},
    hashes::{sha256d, Hash},
    hex::{DisplayHex, FromHex},
    key::Secp256k1,
    opcodes::{
        all::{OP_CAT, OP_EQUAL},
        OP_TRUE,
    },
    secp256k1::rand::rngs::OsRng,
    taproot::{ControlBlock, LeafVersion, TaprootBuilder, TaprootError},
    transaction::Version,
    Address, Amount, Block, BlockHash, CompactTarget, Denomination, OutPoint,
    PublicKey, Script, ScriptBuf, Sequence, Target, Transaction, TxIn,
    TxMerkleNode, TxOut, Txid, Witness,
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use integer_sqrt::IntegerSquareRoot;
use rand::{prelude::SliceRandom, Rng};
use serde::{Deserialize, Serialize};
use serde_tuple::Deserialize_tuple;
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

const DEFAULT_SOCKET_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8332));

#[derive(Clone, Debug, Parser)]
struct RpcAuth {
    /// Bitcoin node RPC pass
    #[arg(long, default_value = "")]
    rpc_pass: String,
    /// Bitcoin node RPC user
    #[arg(long, default_value = "")]
    rpc_user: String,
}

/// Specification for how many invalid txs will be in a block, and the reason
/// that they are invalid
#[derive(Clone, Copy, Debug, Deserialize_tuple)]
struct BlockSpec {
    /// Number of txs with too few stack items for op_cat
    too_few_stack_items: usize,
    /// Number of txs that concatenate two stack elements where the
    /// concatenation exceeds the stack element size limit
    concatenation_exceeds_stack_element_size_limit: usize,
    /// Number of txs that concatenate two stack elements, where the
    /// concatenation is not equal to the third stack element
    concatenation_not_equal: usize,
}

impl BlockSpec {
    fn txs_required(&self) -> usize {
        let BlockSpec {
            too_few_stack_items,
            concatenation_exceeds_stack_element_size_limit,
            concatenation_not_equal,
        } = self;
        too_few_stack_items
            + concatenation_exceeds_stack_element_size_limit
            + concatenation_not_equal
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(transparent)]
struct BlocksSpec(Vec<BlockSpec>);

impl FromStr for BlocksSpec {
    type Err = serde_path_to_error::Error<serde_json::Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut deserializer = serde_json::Deserializer::from_str(s);
        let res = serde_path_to_error::deserialize(&mut deserializer)?;
        Ok(Self(res))
    }
}

#[derive(Subcommand)]
enum Command {
    /// Generate a script
    GenScript {
        /// Socket address for the node RPC server
        #[arg(long, default_value_t = DEFAULT_SOCKET_ADDR)]
        rpc_addr: SocketAddr,
        #[command(flatten)]
        rpc_auth: RpcAuth,
        /// Blocks spec as a JSON string
        blocks_spec: BlocksSpec,
    },
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

#[derive(Debug)]
struct OutputPosixScriptBuilder {
    rpc_addr: SocketAddr,
    rpc_auth: RpcAuth,
    script: Vec<String>,
}

impl OutputPosixScriptBuilder {
    fn new(rpc_addr: SocketAddr, rpc_auth: RpcAuth) -> Self {
        Self {
            rpc_addr,
            rpc_auth,
            script: Vec::new(),
        }
    }

    /// Use curl to send an RPC request to the node
    fn curl_rpc<Params>(
        &mut self,
        comment: Option<&str>,
        method: &str,
        params: Params,
    ) where
        Params: Serialize,
    {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "bip347-enforcer-test",
            "method": method,
            "params": params
        });
        let mut cmd = [
            "curl",
            &format!("'{}'", &self.rpc_addr),
            "-H",
            "'Content-Type: application/json'",
            "--user",
            &format!("'{}:{}'", self.rpc_auth.rpc_user, self.rpc_auth.rpc_pass),
            "--data-binary",
            &format!("'{}'", serde_json::to_string(&request).unwrap()),
        ]
        .join(" ");
        if let Some(comment) = comment {
            cmd = comment
                .lines()
                .map(|line| format!("# {line}"))
                .chain(std::iter::once(cmd))
                .collect::<Vec<_>>()
                .join("\n");
        }
        self.script.push(cmd)
    }

    fn finalize(self) -> String {
        let mut res = self.script.join("\n\n");
        if !res.is_empty() && !res.ends_with('\n') {
            res.push('\n');
        }
        res
    }
}

/// Script with no spend requirements
fn unlocked_script() -> ScriptBuf {
    ScriptBuf::builder().push_opcode(OP_TRUE).into_script()
}

/// Example OP_CAT script that checks that the concatenation of two stack
/// elements is equal to a third stack element
fn op_cat_script() -> ScriptBuf {
    ScriptBuf::builder()
        .push_opcode(OP_CAT)
        .push_opcode(OP_EQUAL)
        .into_script()
}

/// P2TR scriptpubkey and control block
fn op_cat_p2tr() -> (ScriptBuf, ControlBlock) {
    let secp = Secp256k1::new();
    let (_sk, pk) = secp.generate_keypair(&mut OsRng);
    let pk: PublicKey = pk.into();
    let tr_spend_info = TaprootBuilder::new()
        .add_leaf(0, script())
        .unwrap()
        .finalize(&secp, pk.into())
        .unwrap();
    let spk = ScriptBuf::new_p2tr_tweaked(tr_spend_info.output_key());
    let control_block = tr_spend_info
        .control_block(&(script(), LeafVersion::TapScript))
        .unwrap();
    (spk, control_block)
}

const MAX_WITNESS_ELEMENT_SIZE: usize = 520;

/// Spend the OP_CAT outpoint, with the specified witness elements before the
/// script and control block
fn spend_op_cat_outpoint(
    spend_outpoint: OutPoint,
    control_block: ControlBlock,
    mut witness: Witness,
) -> Transaction {
    witness.push(op_cat_script());
    witness.push(control_block.serialize());
    let txin = TxIn {
        previous_output: spend_outpoint,
        witness,
        // FIXME: check this
        ..Default::default()
    };
    let txout = TxOut {
        value: Amount::ONE_SAT,
        script_pubkey: unlocked_script(),
    };
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output: vec![txout],
    }
}

/// Tx spending an `op_cat_script` output with too few stack items in the
/// witness
fn too_few_stack_items_tx(
    spend_outpoint: OutPoint,
    control_block: ControlBlock,
) -> Transaction {
    let mut witness = Witness::new();
    if OsRng.gen() {
        let stack_item_len = OsRng.gen_range(0..=MAX_WITNESS_ELEMENT_SIZE);
        let witness_element: Vec<u8> =
            (0..stack_item_len).map(|_| OsRng.gen()).collect();
        witness.push(witness_element);
    }
    spend_op_cat_outpoint(spend_outpoint, control_block, witness)
}

/// Tx spending an `op_cat_script` output, where the witness includes two
/// elements such that their concatenation exceeds the stack element size limit
fn concatenation_exceeds_stack_element_size_limit_tx(
    spend_outpoint: OutPoint,
    control_block: ControlBlock,
) -> Transaction {
    let mut witness = Witness::new();
    // uniformly sample witness element sizes x, y such that
    // 0 < x <= 520, 0 < y <= 520, 520 < x + y
    let (len0, len1) = loop {
        let len0 = OsRng.gen_range(1..=MAX_WITNESS_ELEMENT_SIZE);
        let len1 = OsRng.gen_range(1..=MAX_WITNESS_ELEMENT_SIZE);
        match (len0 + len1).cmp(&MAX_WITNESS_ELEMENT_SIZE) {
            Ordering::Greater => break (len0, len1),
            Ordering::Equal => continue,
            Ordering::Less =>
            // reflection in y = 520 - x
            {
                break (
                    MAX_WITNESS_ELEMENT_SIZE - len1,
                    MAX_WITNESS_ELEMENT_SIZE - len0,
                )
            }
        }
    };
    let witness0: Vec<u8> = (0..len0).map(|_| OsRng.gen()).collect();
    witness.push(witness0);
    let witness1: Vec<u8> = (0..len1).map(|_| OsRng.gen()).collect();
    witness.push(witness1);
    spend_op_cat_outpoint(spend_outpoint, control_block, witness)
}

/// Tx spending an `op_cat_script` output, where the witness includes two
/// elements such that their concatenation is not equal to the third
fn concatenation_not_equal_tx(
    spend_outpoint: OutPoint,
    control_block: ControlBlock,
) -> Transaction {
    let mut witness = Witness::new();
    // uniformly sample witness element sizes x, y such that
    // 0 <= x <= 520, 0 <= y <= 520, x + y <= 520
    let (len0, len1) = {
        // This is equivalent to uniformly sampling up to T(520+1), where
        // T is the triangle function that computes the kth triangular number,
        // where T(0) = 0.
        // Let r be the triange root of the sample. Then:
        // * x will be 520 - r
        // * y will be T(r) less than the sample.
        let triangle = |k: usize| (k * (k + 1)) / 2;
        let triangle_root = |x: usize| (((8 * x) + 1).integer_sqrt() - 1) / 2;
        let sample = OsRng.gen_range(0..triangle(MAX_WITNESS_ELEMENT_SIZE + 1));
        let r = triangle_root(sample);
        (MAX_WITNESS_ELEMENT_SIZE - r, sample - triangle(r))
    };
    let witness0: Vec<u8> = (0..len0).map(|_| OsRng.gen()).collect();
    let witness1: Vec<u8> = (0..len1).map(|_| OsRng.gen()).collect();
    let concatenated: Vec<u8> = [witness0.clone(), witness1.clone()].concat();
    let claimed_concatenation: Vec<u8> = loop {
        let len = OsRng.gen_range(0..=MAX_WITNESS_ELEMENT_SIZE);
        let bytes = (0..len).map(|_| OsRng.gen()).collect();
        if bytes != concatenated {
            break bytes;
        } else {
            continue;
        }
    };
    witness.push(claimed_concatenation);
    witness.push(witness0);
    witness.push(witness1);
    spend_op_cat_outpoint(spend_outpoint, control_block, witness)
}

fn gen_block(
    prev_blockhash: BlockHash,
    target: CompactTarget,
    txs: Vec<Transaction>,
) -> Block {
    let header = Header {
        version: bitcoin::block::Version::NO_SOFT_FORK_SIGNALLING,
        prev_blockhash,
        merkle_root: TxMerkleNode::all_zeros(),
        time: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32,
        bits: target,
        nonce: 0,
    };
    let mut block = Block {
        header,
        txdata: txs,
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let target = Target::from_compact(target);
    let mut nonce = block.header.nonce;
    let mut header_bytes = bitcoin::consensus::serialize(&block.header);
    loop {
        let header_hash = sha256d::Hash::hash(&header_bytes).to_byte_array();
        if Target::from_le_bytes(header_hash) < target {
            break;
        }
        nonce += 1;
        let nonce_bytes = nonce.to_be_bytes();
        header_bytes[76] = nonce_bytes[0];
        header_bytes[77] = nonce_bytes[1];
        header_bytes[78] = nonce_bytes[2];
        header_bytes[79] = nonce_bytes[3];
    }
    block.header = bitcoin::consensus::deserialize(&header_bytes).unwrap();
    assert!(block.header.validate_pow(target).is_ok());
    block
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InvalidReason {
    TooFewStackItems,
    ConcatenationExceedsStackElementSizeLimit,
    ConcatenationNotEqual,
}

/// Generate N + 1 txs from a block spec.
///
/// The first transaction spends the outpoint to generate N+1 outputs,
/// where N is the number of txs described by the block spec.
/// The first N outputs are 1 sat, and the final output is the remainder.
///
/// The subsequent N txs are described by the block spec, but with randomized
/// order.
fn gen_txs(
    spend_outpoint: OutPoint,
    spend_outpoint_value: Amount,
    block_spec: BlockSpec,
) -> Vec<(Transaction, Option<InvalidReason>)> {
    let first_txin = TxIn {
        previous_output: spend_outpoint,
        // FIXME: check that this is correct
        witness: {
            let mut wit = Witness::new();
            wit.push(unlocked_script());
            wit
        },
        ..Default::default()
    };
    let (mut first_txouts, mut control_blocks): (Vec<_>, VecDeque<_>) = (0
        ..block_spec.txs_required())
        .map(|_| {
            let (script_pubkey, control_block) = op_cat_p2tr();
            let txout = TxOut {
                value: Amount::ONE_SAT,
                script_pubkey,
            };
            (txout, control_block)
        })
        .unzip();
    first_txouts.push(TxOut {
        value: spend_outpoint_value
            - (Amount::ONE_SAT * block_spec.txs_required() as u64),
        script_pubkey: ScriptBuf::new_p2wsh(&unlocked_script().wscript_hash()),
    });
    let first_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![first_txin],
        output: first_txouts,
    };
    let first_txid = first_tx.compute_txid();
    let mut res = Vec::new();
    let mut vout = 0;
    for _ in 0..block_spec.too_few_stack_items {
        let spend_outpoint = OutPoint {
            txid: first_txid,
            vout,
        };
        vout += 1;
        let control_block = control_blocks.pop_front().unwrap();
        let tx = too_few_stack_items_tx(spend_outpoint, control_block);
        res.push((tx, Some(InvalidReason::TooFewStackItems)));
    }
    for _ in 0..block_spec.concatenation_exceeds_stack_element_size_limit {
        let spend_outpoint = OutPoint {
            txid: first_txid,
            vout,
        };
        vout += 1;
        let control_block = control_blocks.pop_front().unwrap();
        let tx = concatenation_exceeds_stack_element_size_limit_tx(
            spend_outpoint,
            control_block,
        );
        res.push((
            tx,
            Some(InvalidReason::ConcatenationExceedsStackElementSizeLimit),
        ));
    }
    for _ in 0..block_spec.concatenation_not_equal {
        let spend_outpoint = OutPoint {
            txid: first_txid,
            vout,
        };
        vout += 1;
        let control_block = control_blocks.pop_front().unwrap();
        let tx = concatenation_not_equal_tx(spend_outpoint, control_block);
        res.push((tx, Some(InvalidReason::ConcatenationNotEqual)));
    }
    // Randomize order
    res.shuffle(&mut OsRng);
    // Add first tx and reverse so that it is first in the result
    res.push((first_tx, None));
    res.reverse();
    res
}

fn block_subsidy(network: bitcoin::Network, height: u32) -> Amount {
    #[allow(clippy::wildcard_in_or_patterns)]
    let halving_interval = match network {
        bitcoin::Network::Regtest => 150,
        bitcoin::Network::Bitcoin | bitcoin::Network::Testnet | _ => {
            SUBSIDY_HALVING_INTERVAL
        }
    };
    let epoch = height / halving_interval;
    Amount::from_int_btc(50) / (1 << epoch)
}

fn explain_tx_invalid(
    tx: &Transaction,
    invalid_reason: InvalidReason,
) -> String {
    let mut res = Vec::new();
    let tx_json = serde_json::to_string(&tx).unwrap();
    res.push(format!("tx JSON: {tx_json}"));
    let witness = &tx.input[0].witness;
    res.push(format!(
        "witness script: {}",
        Script::from_bytes(witness.second_to_last().unwrap()).to_asm_string()
    ));
    match invalid_reason {
        InvalidReason::TooFewStackItems => {
            let witness_stack_size = witness.len() - 2;
            res.push(format!("witness stack size: {witness_stack_size}"));
            for idx in 0..witness_stack_size {
                let stack_item =
                    witness.nth(witness_stack_size - 1 - idx).unwrap();
                res.push(format!(
                    "witness stack item {idx}: {}",
                    stack_item.to_lower_hex_string()
                ));
            }
        }
        InvalidReason::ConcatenationExceedsStackElementSizeLimit => {
            const WITNESS_STACK_SIZE: usize = 2;
            for idx in 0..WITNESS_STACK_SIZE {
                let stack_item =
                    witness.nth(WITNESS_STACK_SIZE - 1 - idx).unwrap();
                res.push(format!(
                    "witness stack item {idx} ({} bytes): {}",
                    stack_item.len(),
                    stack_item.to_lower_hex_string()
                ));
            }
        }
        InvalidReason::ConcatenationNotEqual => {
            const WITNESS_STACK_SIZE: usize = 3;
            for idx in 0..WITNESS_STACK_SIZE {
                let stack_item =
                    witness.nth(WITNESS_STACK_SIZE - 1 - idx).unwrap();
                res.push(format!(
                    "witness stack item {idx}: {}",
                    stack_item.to_lower_hex_string()
                ));
            }
        }
    }
    res.join("\n")
}

async fn gen_script(
    network: bitcoin::Network,
    rpc_addr: SocketAddr,
    rpc_auth: RpcAuth,
    blocks_spec: BlocksSpec,
) -> anyhow::Result<()> {
    let mut posix_script_builder =
        OutputPosixScriptBuilder::new(rpc_addr, rpc_auth.clone());
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
    let client = bip300301::client(
        rpc_addr,
        &rpc_auth.rpc_pass,
        Some(REQUEST_TIMEOUT),
        &rpc_auth.rpc_user,
    )?;
    let BlockTemplate {
        height,
        prev_blockhash,
        target,
        ..
    } = client.get_block_template(Default::default()).await?;
    let prev_blockhash = BlockHash::from_byte_array(*prev_blockhash.as_ref());
    let addr = Address::p2wsh(&unlocked_script(), network);
    let coinbase_txin = TxIn {
        previous_output: OutPoint::null(),
        script_sig: ScriptBuf::builder().push_int(height as i64).into_script(),
        // FIXME: Verify that this is correct
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };
    let coinbase_value = block_subsidy(network, height);
    let coinbase_txout = TxOut {
        value: coinbase_value,
        script_pubkey: addr.script_pubkey(),
    };
    let coinbase_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_height(height + COINBASE_MATURITY)?,
        input: vec![coinbase_txin],
        output: vec![coinbase_txout],
    };
    let coinbase_txid = coinbase_tx.compute_txid();
    let block = gen_block(
        prev_blockhash,
        CompactTarget::from_consensus(target.to_consensus()),
        vec![coinbase_tx],
    );
    // Generate some blocks so that an output is available to spend
    posix_script_builder.curl_rpc(
        Some("Mine a block, so that the coinbase output can be used in later txs"),
        "submitblock",
        [ bitcoin::consensus::serialize(&block).to_lower_hex_string() ],
    );
    posix_script_builder.curl_rpc(
        Some("Generate some blocks, so that the coinbase output is available to spend"),
        "generatetoaddress",
        [
            serde_json::Value::Number(COINBASE_MATURITY.into()),
            serde_json::Value::String(addr.to_string()),
        ],
    );
    let mut spend_outpoint = OutPoint {
        txid: coinbase_txid,
        vout: 0,
    };
    let mut spend_outpoint_value = coinbase_value;
    for block_spec in blocks_spec.0.into_iter() {
        let txs = gen_txs(spend_outpoint, spend_outpoint_value, block_spec);
        spend_outpoint = OutPoint {
            txid: txs[0].0.compute_txid(),
            vout: txs[0].0.output.len() as u32 - 1,
        };
        spend_outpoint_value = txs[0].0.output.last().unwrap().value;
        let raw_txs: Vec<_> = txs
            .iter()
            .map(|(tx, _)| {
                bitcoin::consensus::serialize(tx).to_lower_hex_string()
            })
            .collect();
        let mut comment = format!(
            "Generate a block with {} failing txs: \n\
             - {} txs with too few stack items\n\
             - {} txs where the concatenation of two stack items exceeds the stack item size limit\n\
             - {} txs where the concatenation of two stack items is not equal to the third",
            block_spec.txs_required(),
            block_spec.too_few_stack_items,
            block_spec.concatenation_exceeds_stack_element_size_limit,
            block_spec.concatenation_not_equal
        );
        for (idx, (tx, invalid_reason)) in txs.iter().enumerate() {
            let Some(invalid_reason) = invalid_reason else {
                continue;
            };
            comment.push_str(&format!(
                "\n\ntx {idx}:\n{}",
                explain_tx_invalid(tx, *invalid_reason)
            ));
        }
        posix_script_builder.curl_rpc(
            Some(&comment),
            "generateblock",
            serde_json::json!([addr.to_string(), raw_txs]),
        );
    }
    println!("{}", posix_script_builder.finalize());
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::P2trAddress => p2tr_address(cli.network.into()),
        Command::Spend(spend_args) => spend(cli.network.into(), *spend_args)?,
        Command::GenScript {
            rpc_addr,
            rpc_auth,
            blocks_spec,
        } => {
            gen_script(cli.network.into(), rpc_addr, rpc_auth, blocks_spec)
                .await?
        }
    }
    Ok(())
}
