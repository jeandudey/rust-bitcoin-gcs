# rust-bitcoin-gcs - BIP-0158 implementation

Rust implementation of
[*Compact Block Filters for Light Clients (BIP-0158)*][bip0158]. This crate is
intended to be used by bitcoin daemons and clients.

[bip0158]: https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki

## Creating filters

To enable filter creation from [bitcoin][1] data types you need to use the 
`builder` flag.

[1]: https://github.com/rust-bitcoin/rust-bitcoin
