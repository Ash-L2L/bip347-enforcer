use std::collections::HashMap;

use libc::c_uint;
use thiserror::Error;

mod ffi {
    use libc::{c_uchar, c_uint};

    #[repr(C)]
    pub(super) struct VerifyScriptResult {
        pub success: bool,
        pub err_msg: *const libc::c_char,
    }

    // Implement a Drop trait to ensure the C++ side frees allocated resources
    impl Drop for VerifyScriptResult {
        fn drop(&mut self) {
            unsafe {
                free_verify_script_result(self);
            }
        }
    }

    impl From<&VerifyScriptResult> for Result<(), String> {
        fn from(res: &VerifyScriptResult) -> Self {
            if res.success {
                Ok(())
            } else {
                let err_c_str =
                    unsafe { std::ffi::CStr::from_ptr(res.err_msg) };
                Err(err_c_str.to_str().unwrap().to_owned())
            }
        }
    }

    #[link(name = "bitcoin-script.a", kind = "static")]
    extern "C" {
        #[allow(dead_code)]
        pub fn mandatory_script_verify_flags() -> u32;

        #[allow(dead_code)]
        pub fn standard_script_verify_flags() -> u32;

        pub fn op_cat_verify_flag() -> u32;

        pub fn verify_script(
            scriptPubKey: *const c_uchar,
            scriptPubKeyLen: c_uint,
            txTo: *const c_uchar,
            txToLen: c_uint,
            nIn: c_uint,
            flags: c_uint,
            amount: i64,
        ) -> *mut VerifyScriptResult;

        /// MUST be called when VerifyScriptResult is dropped
        pub(super) fn free_verify_script_result(
            result: *mut VerifyScriptResult,
        );
    }
}

#[allow(dead_code)]
pub fn mandatory_script_verify_flags() -> u32 {
    unsafe { ffi::mandatory_script_verify_flags() }
}

#[allow(dead_code)]
pub fn standard_script_verify_flags() -> u32 {
    unsafe { ffi::standard_script_verify_flags() }
}

pub fn op_cat_verify_flag() -> u32 {
    unsafe { ffi::op_cat_verify_flag() }
}

pub fn verify(
    script_pub_key: &[u8],
    tx_to: &[u8],
    n_in: u32,
    flags: u32,
    amount: i64,
) -> Result<(), String> {
    unsafe {
        &*ffi::verify_script(
            script_pub_key.as_ptr(),
            script_pub_key.len() as c_uint,
            tx_to.as_ptr(),
            tx_to.len() as c_uint,
            n_in as c_uint,
            flags as c_uint,
            amount,
        )
    }
    .into()
}

#[derive(Debug, Error)]
#[error("Error verifying input {input_idx}: {err_msg}")]
pub struct VerifyTxError {
    /// Index of the input that failed verification
    pub input_idx: usize,
    /// Source error message
    pub err_msg: String,
}

/// Verify tx
pub fn verify_tx(
    tx: &bitcoin::Transaction,
    spent_outputs: &HashMap<bitcoin::Txid, bitcoin::Transaction>,
    flags: u32,
) -> Result<(), VerifyTxError> {
    let tx_encoded = bitcoin::consensus::serialize(tx);
    let get_spent_output = |outpoint: &bitcoin::OutPoint| {
        &spent_outputs[&outpoint.txid].output[outpoint.vout as usize]
    };
    for (input_idx, input) in tx.input.iter().enumerate() {
        let spent_output = get_spent_output(&input.previous_output);
        let spk_encoded = &spent_output.script_pubkey.to_bytes();
        if let Err(err_msg) = verify(
            spk_encoded,
            &tx_encoded,
            input_idx as u32,
            flags,
            spent_output.value.to_sat() as i64,
        ) {
            return Err(VerifyTxError { input_idx, err_msg });
        } else {
            continue;
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use anyhow::anyhow;
    use bitcoin::{
        absolute::LockTime,
        ecdsa::Signature,
        hex::FromHex,
        opcodes::all::{OP_CAT, OP_EQUAL},
        secp256k1::{rand::rngs::OsRng, Secp256k1},
        sighash::SighashCache,
        taproot::{LeafVersion, TaprootBuilder},
        transaction::Version,
        Amount, EcdsaSighashType, OutPoint, PublicKey, ScriptBuf, Transaction,
        TxIn, TxOut, Witness,
    };

    use super::*;

    /// Generate a tx with 0 inputs and 1 output,
    /// with the specified scriptpubkey.
    fn tx_0_in_1_out(script_pubkey: ScriptBuf, value: Amount) -> Transaction {
        let txout = TxOut {
            value,
            script_pubkey,
        };
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_height(1).unwrap(),
            input: Vec::new(),
            output: vec![txout],
        }
    }

    /// Generate a tx with 1 input and 1 output,
    /// with the specified scriptpubkey and value.
    /// The tx input does not include a script sig or witness.
    fn tx_1_in_1_out(
        previous_output: OutPoint,
        script_pubkey: ScriptBuf,
        value: Amount,
    ) -> Transaction {
        let txin = TxIn {
            previous_output,
            ..Default::default()
        };
        let txout = TxOut {
            value,
            script_pubkey,
        };
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_height(1).unwrap(),
            input: vec![txin],
            output: vec![txout],
        }
    }

    #[test]
    fn verify_1_in_1_out() -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut OsRng);
        let pk: PublicKey = pk.into();
        let wpkh = pk.wpubkey_hash()?;
        let spk = ScriptBuf::new_p2wpkh(&wpkh);
        let value = Amount::from_int_btc(123);
        // source tx for the input
        let source_tx = tx_0_in_1_out(spk.clone(), value);
        let tx = {
            let previous_output = OutPoint {
                txid: source_tx.compute_txid(),
                vout: 0,
            };
            tx_1_in_1_out(previous_output, spk.clone(), value)
        };
        let mut sighash_cache = SighashCache::new(tx);
        let sighash = sighash_cache.p2wpkh_signature_hash(
            0,
            &spk,
            sighash_cache.transaction().output[0].value,
            EcdsaSighashType::All,
        )?;
        let mut sig = Secp256k1::new().sign_ecdsa_low_r(&sighash.into(), &sk);
        sig.normalize_s();
        let wit = Witness::p2wpkh(&Signature::sighash_all(sig), &pk.inner);
        let txin_0_wit = sighash_cache
            .witness_mut(0)
            .ok_or(anyhow::anyhow!("Failed to get witness for txin 0"))?;
        *txin_0_wit = wit;
        let tx = sighash_cache.into_transaction();
        let spent_outputs =
            HashMap::from_iter([(source_tx.compute_txid(), source_tx)]);
        // sanity checks that tx is valid
        {
            tx.verify(|outpoint| {
                let tx = spent_outputs.get(&outpoint.txid)?;
                tx.output.get(outpoint.vout as usize).cloned()
            })?;
        }

        // verify tx
        assert!(verify_tx(&tx, &spent_outputs, op_cat_verify_flag()).is_ok());
        Ok(())
    }

    // OP_CAT on an empty stack should fail if OP_CAT is enabled,
    // and succeed if disabled
    #[test]
    fn verify_op_cat_empty_stack() -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        let (_sk, pk) = secp.generate_keypair(&mut OsRng);
        let pk: PublicKey = pk.into();
        let script = ScriptBuf::builder().push_opcode(OP_CAT).into_script();
        let tr_spend_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())?
            .finalize(&secp, pk.into())
            .map_err(|_| {
                anyhow::anyhow!("failed to finalize taproot script")
            })?;
        let spk = ScriptBuf::new_p2tr_tweaked(tr_spend_info.output_key());
        let value = Amount::from_int_btc(123);
        // source tx for the input
        let source_tx = tx_0_in_1_out(spk.clone(), value);
        let tx = {
            let previous_output = OutPoint {
                txid: source_tx.compute_txid(),
                vout: 0,
            };
            tx_1_in_1_out(previous_output, spk.clone(), value)
        };
        let mut sighash_cache = SighashCache::new(tx);
        let control_block = tr_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or(anyhow!("Expected a control block"))?;
        assert!(control_block.verify_taproot_commitment(
            &secp,
            tr_spend_info.output_key().into(),
            &script
        ));
        let mut wit = Witness::new();
        wit.push(script);
        wit.push(control_block.serialize());
        let txin_0_wit = sighash_cache
            .witness_mut(0)
            .ok_or(anyhow::anyhow!("Failed to get witness for txin 0"))?;
        *txin_0_wit = wit;
        let tx = sighash_cache.into_transaction();
        let spent_outputs: HashMap<bitcoin::Txid, Transaction> =
            HashMap::from_iter([(source_tx.compute_txid(), source_tx)]);
        // verify tx without OP_CAT enabled should work
        assert!(verify_tx(
            &tx,
            &spent_outputs,
            standard_script_verify_flags() ^ op_cat_verify_flag()
        )
        .is_ok());
        // verify tx with OP_CAT enabled should fail
        assert!(
            verify_tx(&tx, &spent_outputs, standard_script_verify_flags())
                .is_err()
        );
        Ok(())
    }

    // OP_CAT on a stack with two elements should succeed if OP_CAT is enabled
    #[test]
    fn verify_op_cat_two_elements() -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        let (_sk, pk) = secp.generate_keypair(&mut OsRng);
        let pk: PublicKey = pk.into();
        let script = ScriptBuf::builder().push_opcode(OP_CAT).into_script();
        let tr_spend_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())?
            .finalize(&secp, pk.into())
            .map_err(|_| {
                anyhow::anyhow!("failed to finalize taproot script")
            })?;
        let spk = ScriptBuf::new_p2tr_tweaked(tr_spend_info.output_key());
        let value = Amount::from_int_btc(123);
        // source tx for the input
        let source_tx = tx_0_in_1_out(spk.clone(), value);
        let tx = {
            let previous_output = OutPoint {
                txid: source_tx.compute_txid(),
                vout: 0,
            };
            tx_1_in_1_out(previous_output, spk.clone(), value)
        };
        let mut sighash_cache = SighashCache::new(tx);
        let control_block = tr_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or(anyhow!("Expected a control block"))?;
        assert!(control_block.verify_taproot_commitment(
            &secp,
            tr_spend_info.output_key().into(),
            &script
        ));
        let mut wit = Witness::new();
        wit.push([0xaa]);
        wit.push([0xbb]);
        wit.push(script);
        wit.push(control_block.serialize());
        let txin_0_wit = sighash_cache
            .witness_mut(0)
            .ok_or(anyhow::anyhow!("Failed to get witness for txin 0"))?;
        *txin_0_wit = wit;
        let tx = sighash_cache.into_transaction();
        let spent_outputs: HashMap<bitcoin::Txid, Transaction> =
            HashMap::from_iter([(source_tx.compute_txid(), source_tx)]);
        // verify tx with OP_CAT enabled should succeed
        assert!(
            verify_tx(&tx, &spent_outputs, standard_script_verify_flags())
                .is_ok()
        );
        Ok(())
    }

    // OP_CAT on a stack with two elements, compared with their concatenation,
    // should succeed if OP_CAT is enabled
    #[test]
    fn verify_op_cat_two_elements_eq() -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        let (_sk, pk) = secp.generate_keypair(&mut OsRng);
        let pk: PublicKey = pk.into();
        let script = ScriptBuf::builder()
            .push_opcode(OP_CAT)
            .push_opcode(OP_EQUAL)
            .into_script();
        let tr_spend_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())?
            .finalize(&secp, pk.into())
            .map_err(|_| {
                anyhow::anyhow!("failed to finalize taproot script")
            })?;
        let spk = ScriptBuf::new_p2tr_tweaked(tr_spend_info.output_key());
        let value = Amount::from_int_btc(123);
        let source_tx = tx_0_in_1_out(spk.clone(), value);
        let tx = {
            let previous_output = OutPoint {
                txid: source_tx.compute_txid(),
                vout: 0,
            };
            tx_1_in_1_out(previous_output, spk.clone(), value)
        };
        let mut sighash_cache = SighashCache::new(tx);
        let control_block = tr_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or(anyhow!("Expected a control block"))?;
        assert!(control_block.verify_taproot_commitment(
            &secp,
            tr_spend_info.output_key().into(),
            &script
        ));
        let mut wit = Witness::new();
        wit.push(Vec::<u8>::from_hex("78a11a1260c1101260")?);
        wit.push(Vec::<u8>::from_hex("78a11a1260")?);
        wit.push(Vec::<u8>::from_hex("c1101260")?);
        wit.push(script);
        wit.push(control_block.serialize());
        let txin_0_wit = sighash_cache
            .witness_mut(0)
            .ok_or(anyhow::anyhow!("Failed to get witness for txin 0"))?;
        *txin_0_wit = wit;
        let tx = sighash_cache.into_transaction();
        let spent_outputs: HashMap<bitcoin::Txid, Transaction> =
            HashMap::from_iter([(source_tx.compute_txid(), source_tx)]);
        // verify tx with OP_CAT enabled should succeed
        assert!(
            verify_tx(&tx, &spent_outputs, standard_script_verify_flags())
                .is_ok()
        );
        Ok(())
    }

    // OP_CAT on a stack with two elements, compared with something other than
    // their concatenation, should fail if OP_CAT is enabled, and succeed
    // if OP_CAT is not enabled
    #[test]
    fn verify_op_cat_two_elements_neq() -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        let (_sk, pk) = secp.generate_keypair(&mut OsRng);
        let pk: PublicKey = pk.into();
        let script = ScriptBuf::builder()
            .push_opcode(OP_CAT)
            .push_opcode(OP_EQUAL)
            .into_script();
        let tr_spend_info = TaprootBuilder::new()
            .add_leaf(0, script.clone())?
            .finalize(&secp, pk.into())
            .map_err(|_| {
                anyhow::anyhow!("failed to finalize taproot script")
            })?;
        let spk = ScriptBuf::new_p2tr_tweaked(tr_spend_info.output_key());
        let value = Amount::from_int_btc(123);
        let source_tx = tx_0_in_1_out(spk.clone(), value);
        let tx = {
            let previous_output = OutPoint {
                txid: source_tx.compute_txid(),
                vout: 0,
            };
            tx_1_in_1_out(previous_output, spk.clone(), value)
        };
        let mut sighash_cache = SighashCache::new(tx);
        let control_block = tr_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or(anyhow!("Expected a control block"))?;
        assert!(control_block.verify_taproot_commitment(
            &secp,
            tr_spend_info.output_key().into(),
            &script
        ));
        let mut wit = Witness::new();
        wit.push(Vec::<u8>::from_hex("")?);
        wit.push(Vec::<u8>::from_hex("78a11a1260")?);
        wit.push(Vec::<u8>::from_hex("c1101260")?);
        wit.push(script);
        wit.push(control_block.serialize());
        let txin_0_wit = sighash_cache
            .witness_mut(0)
            .ok_or(anyhow::anyhow!("Failed to get witness for txin 0"))?;
        *txin_0_wit = wit;
        let tx = sighash_cache.into_transaction();
        let spent_outputs: HashMap<bitcoin::Txid, Transaction> =
            HashMap::from_iter([(source_tx.compute_txid(), source_tx)]);
        // verify tx with OP_CAT disabled should succeed
        assert!(verify_tx(
            &tx,
            &spent_outputs,
            standard_script_verify_flags() ^ op_cat_verify_flag()
        )
        .is_ok());
        // verify tx with OP_CAT enabled should fail
        assert!(
            verify_tx(&tx, &spent_outputs, standard_script_verify_flags())
                .is_err()
        );
        Ok(())
    }
}
