# BIP347 Enforcer

## Build

* Install dependencies (rustup)
* Clone this repository
* Init submodules `git submodule update --init --recursive`
* Build with `cargo build` or `cargo build --release`

### Optional
To compile with mempool enforcer support, use `cargo build --features=mempool` or `cargo build --release --features=mempool`.

## Configure Bitcoin node
* Must use a version of Bitcoin Core more recent than `75118a608fc22a57567743000d636bc1f969f748`.
* RPC server MUST be enabled.
* ZMQ rawblock publishing MUST be enabled.
* `txindex` MUST be enabled.

If the mempool feature is enabled:
* ZMQ sequence publishing MUST be enabled.

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

Extra options are required if the mempool feature is enabled.

# Demo tool
For options, run `gen-demo-tx --help`.

Typical usage:
```
gen-demo-tx gen-script \
  --network regtest \
  --rpc-addr "127.0.0.1:8332" \
  --rpc-user "user" \
  --rpc-pass "pass" \
  "[[1, 1, 1], [2, 2, 2]]"
```

### Blocks Spec
The blocks specification is a JSON array of triples (also JSON arrays) of integers, where:
* The first integer is the number of txs that should have too few items in the witness, such that `OP_CAT` is called on a stack with less than 2 stack items
* The second integer is the number of txs that should have two witness stack
elements such that their concatenation is longer than the stack item size limit
* The third integer is the number of txs that should have witness stack items
such that two concatenated stack items do not match the third witness stack item.
Each triple describes a sequential block that will be constructed by the demo tool.