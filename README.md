# BIP347 Enforcer

## Build

* Install dependencies (rustup)
* Clone this repository
* Init submodules `git submodule update --init --recursive`
* Build with `cargo build`

## Configure Bitcoin node
Must use a version of Bitcoin Core more recent than `75118a608fc22a57567743000d636bc1f969f748`
RPC server MUST be enabled.
ZMQ rawblock publishing MUST be enabled.
`txindex` MUST be enabled.
