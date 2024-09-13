use std::{env, process::Command};

fn build_secp256k1() {
    let target = env::var("TARGET").expect("TARGET was not set");
    let mut builder = cc::Build::new();
    builder
        .opt_level(1)
        .flag_if_supported("-Wno-unused-function")
        .define("ENABLE_MODULE_EXTRAKEYS", "1")
        .define("ENABLE_MODULE_RECOVERY", "1")
        .define("ENABLE_MODULE_SCHNORRSIG", "1")
        .include("depends/bitcoin/src/secp256k1/include")
        .include("depends/bitcoin/src/secp256k1/src")
        .file("depends/bitcoin/src/secp256k1/src/precomputed_ecmult.c")
        .file("depends/bitcoin/src/secp256k1/src/secp256k1.c");
    if target.contains("windows") {
        builder.define("WIN32", "1");
    }
    builder.compile("libsecp256k1.a")
}

// Run `autogen.sh` and `configure` scripts for Bitcoin
fn configure_bitcoin() {
    // Set the Bitcoin source directory
    static SOURCE_DIR: &str = "depends/bitcoin";

    let out_dir = env::var("OUT_DIR").unwrap();

    // Run the configure script to generate config headers
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "cd {SOURCE_DIR} && ./autogen.sh && ./configure --with-secp256k1={out_dir}"
        ))
        .status()
        .expect("failed to configure Bitcoin Core");

    if !status.success() {
        panic!("Bitcoin Core configuration failed");
    }
}

fn main() {
    build_secp256k1();

    configure_bitcoin();

    let out_dir = env::var("OUT_DIR").unwrap();

    let target = env::var("TARGET").expect("TARGET was not set");
    let mut builder = cc::Build::new();
    builder
        .cpp(true)
        .flag("-std=c++20")
        .opt_level(1)
        .flag("-Wno-unused-parameter")
        .include(&out_dir)
        .include("depends/bitcoin/src")
        .include("depends/bitcoin/src/secp256k1/include")
        .file("depends/bitcoin/src/crypto/ripemd160.cpp")
        .file("depends/bitcoin/src/crypto/sha1.cpp")
        .file("depends/bitcoin/src/crypto/sha256.cpp")
        .file("depends/bitcoin/src/hash.cpp")
        .file("depends/bitcoin/src/pubkey.cpp")
        .file("depends/bitcoin/src/primitives/transaction.cpp")
        .file("depends/bitcoin/src/script/interpreter.cpp")
        .file("depends/bitcoin/src/script/script.cpp")
        .file("depends/bitcoin/src/script/script_error.cpp")
        .file("depends/bitcoin/src/support/cleanse.cpp")
        .file("depends/bitcoin/src/uint256.cpp")
        .file("depends/bitcoin/src/util/strencodings.cpp")
        .file("stubs/bitcoin-script.cpp");
    if target.contains("windows") {
        builder.define("WIN32", "1");
    }
    builder.compile("bitcoin-script.a");

    println!("cargo:include=depends/bitcoin/src");
    println!("cargo:rerun-if-changed=stubs/bitcoin-script.cpp");
    println!("cargo:rustc-link-lib=static=secp256k1");
    println!("cargo:rustc-link-search=native=depends/bitcoin/src/.libs");
    println!("cargo:rustc-link-search=native={}", out_dir);
}
