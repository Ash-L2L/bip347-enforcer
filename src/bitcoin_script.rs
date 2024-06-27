use libc::{c_uint, c_uchar};

#[link(name = "bitcoin-script.a", kind = "static")]
extern "C" {
    fn verify_script(scriptPubKey: *const c_uchar, scriptPubKeyLen: c_uint,
                     txTo: *const c_uchar, txToLen: c_uint,
                     nIn: c_uint, flags: c_uint, amount: i64) -> bool;
}

pub fn verify(script_pub_key: &[u8], tx_to: &[u8], n_in: u32, flags: u32, amount: i64) -> bool {
    unsafe {
        verify_script(script_pub_key.as_ptr(), script_pub_key.len() as c_uint,
                      tx_to.as_ptr(), tx_to.len() as c_uint,
                      n_in as c_uint, flags as c_uint, amount)
    }
}