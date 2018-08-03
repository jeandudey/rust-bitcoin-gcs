extern crate bitcoin;
extern crate bitcoin_gcs;
extern crate serde_json;

extern crate hex;

use std::io::Cursor;

use bitcoin::blockdata::block::Block;
use bitcoin::network::encodable::ConsensusDecodable;
use bitcoin::network::serialize::RawDecoder;
use bitcoin::util::hash::Sha256dHash;

use serde_json::Value;

const TESTNET_19: &'static str = include_str!("testnet-19.json");

#[test]
fn testnet_19() {
    let json: Value = serde_json::from_str(TESTNET_19)
        .expect("invalid test vector");

    let data = json.as_array().expect("invalid test vector");

    let tv = data[1].as_array().expect("invalid test vector");
    let tv = TestVector::from_json(tv);

    println!("{:?}", tv);

    let filter = bitcoin_gcs::builder::build_basic_filter(&tv.block);

    assert_eq!(filter.as_bytes(), tv.basicfilter.as_bytes());
}

#[derive(Debug)]
struct TestVector {
    pub blockheight: u64,
    pub blockhash: Sha256dHash,
    pub block: Block,
    pub prevoutputscriptsforblock: Value,
    pub previousbasicheader: String,
    pub basicfilter: bitcoin_gcs::Filter,
    pub basicheader: String,
    pub notes: String,
}

impl TestVector {
    fn from_json(v: &Vec<Value>) -> TestVector {
        let blockheight = v[0].as_u64().expect("Block Height");
        let blockhash = v[1].as_str()
            .map(|b| {
                Sha256dHash::from_hex(b).expect("invalid hash")
            })
            .expect("Block Hash");
        let block = v[2].as_str()
            .map(|v| {
                // Parse a block, the format is specified in btcd/wire/msgblock.go

                let raw = hex::decode(v).expect("invalid hex string");
                let mut d = RawDecoder::new(Cursor::new(raw));
                Block::consensus_decode(&mut d).expect("couldn't read block")
            })
            .expect("Block");
        let prevoutputscriptsforblock = v[3].clone();
        let previousbasicheader = v[4].as_str().map(|v| v.to_string()).expect("Previous Basic Header");
        let basicfilter = v[5].as_str()
            .map(|v| {
                let raw = hex::decode(v).expect("invalid hex string");
                bitcoin_gcs::Filter::from_nbytes(bitcoin_gcs::DEFAULT_P, &raw)
                    .expect("invalid filter")
            })
            .expect("Basic Filter");
        let basicheader = v[6].as_str().map(|v| v.to_string()).expect("Basic Header");
        let notes = v[7].as_str().map(|v| v.to_string()).expect("Notes");

        TestVector {
            blockheight,
            blockhash,
            block,
            prevoutputscriptsforblock,
            previousbasicheader,
            basicfilter,
            basicheader,
            notes,
        }
    }
}
