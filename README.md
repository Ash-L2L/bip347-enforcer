# BIP347 Enforcer

## Build

* Install dependencies (rustup)
* Clone this repository
* Init submodules `git submodule update --init --recursive`
* Build with `cargo build` or `cargo build --release`

## Configure Bitcoin node
* Must use a version of Bitcoin Core more recent than `75118a608fc22a57567743000d636bc1f969f748`.
* RPC server MUST be enabled.
* ZMQ rawblock publishing MUST be enabled.
* `txindex` MUST be enabled.

## Run
For options, run `bip347-enforcer --help`.

Typical usage:
```
bip347-enforcer \
  --rpc-addr "127.0.0.1:8332" \
  --rpc-user "user" \
  --rpc-pass "pass" \
  --zmq-addr-rawblock "tcp://127.0.0.1:28332" \
  --log-level DEBUG
```
