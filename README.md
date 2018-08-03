# rust-bitcoin-gcs - BIP-0158 implementation

Rust implementation of
[*Compact Block Filters for Light Clients (BIP-0158)*][bip0158]. This crate is
intended to be used by bitcoin daemons and clients.

[bip0158]: https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki

## Features

- `builder`: Enables the construction of GCS filters from [*rust-bitcoin*][1]
types.
- `decode`: Enables the decoding of `Filters` from bytes.

[1]: https://github.com/rust-bitcoin/rust-bitcoin
