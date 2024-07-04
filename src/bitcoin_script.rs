use std::collections::HashMap;

use libc::c_uint;

mod ffi {
    use libc::{c_uchar, c_uint};

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
        ) -> bool;
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
) -> bool {
    unsafe {
        ffi::verify_script(
            script_pub_key.as_ptr(),
            script_pub_key.len() as c_uint,
            tx_to.as_ptr(),
            tx_to.len() as c_uint,
            n_in as c_uint,
            flags as c_uint,
            amount,
        )
    }
}

/// Verify tx
pub fn verify_tx(
    tx: &bitcoin::Transaction,
    spent_outputs: &HashMap<bitcoin::Txid, bitcoin::Transaction>,
    flags: u32,
) -> bool {
    let tx_encoded = bitcoin::consensus::serialize(tx);
    let get_spent_output = |outpoint: &bitcoin::OutPoint| {
        &spent_outputs[&outpoint.txid].output[outpoint.vout as usize]
    };
    for (idx, input) in tx.input.iter().enumerate() {
        let spent_output = get_spent_output(&input.previous_output);
        let spk_encoded =
            bitcoin::consensus::serialize(&spent_output.script_pubkey);
        if !verify(
            &spk_encoded,
            &tx_encoded,
            idx as u32,
            flags,
            spent_output.value.to_sat() as i64,
        ) {
            return false;
        } else {
            continue;
        }
    }
    true
}

#[cfg(test)]
mod test {
    use bitcoin::{
        absolute::LockTime,
        ecdsa::Signature,
        secp256k1::{rand::rngs::OsRng, Secp256k1},
        sighash::SighashCache,
        transaction::Version,
        Amount, EcdsaSighashType, OutPoint, PublicKey, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Witness,
    };

    use super::*;

    #[test]
    fn verify_1_in_1_out() -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut OsRng);
        let pk: PublicKey = pk.into();
        let wpkh = pk.wpubkey_hash()?;
        let spk = ScriptBuf::new_p2wpkh(&wpkh);
        let value = Amount::from_int_btc(123);
        let source_txout = TxOut {
            value,
            script_pubkey: spk.clone(),
        };
        // source tx for the input
        let source_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_height(1)?,
            input: Vec::new(),
            output: vec![source_txout.clone()],
        };
        let source_outpoint = OutPoint {
            txid: source_tx.compute_txid(),
            vout: 0,
        };
        let txin = TxIn {
            previous_output: source_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::default(),
            witness: Witness::new(),
        };
        let txout = TxOut {
            value,
            script_pubkey: spk.clone(),
        };
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_height(1)?,
            input: vec![txin],
            output: vec![txout],
        };
        let mut sighash_cache = SighashCache::new(tx);
        let sighash = sighash_cache.p2wpkh_signature_hash(
            0,
            &spk,
            value,
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
        assert!(verify_tx(&tx, &spent_outputs, op_cat_verify_flag()));
        Ok(())
    }
}
