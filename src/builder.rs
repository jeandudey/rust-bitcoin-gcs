use bitcoin::blockdata::block::Block;
use bitcoin::blockdata::transaction::TxOutRef;
use bitcoin::network::serialize::BitcoinHash;
use bitcoin::util::hash::Sha256dHash;

use byteorder::{LittleEndian, ByteOrder};

use {DEFAULT_P, Filter};

/// A GCS filter builder.
#[derive(Debug)]
pub struct Builder {
    p: u8,
    key: (u64, u64),
    data: Vec<Vec<u8>>,
}

impl Builder {
    // Constructors

    /// Creates a new `Builder`.
    pub fn new() -> Builder {
        Builder {
            p: 0,
            key: (0, 0),
            data: Vec::new(),
        }
    }

    // Building functions

    /// This functions derives a key from a `Sha256dHash` by truncating the
    /// bytes truncating the hash to the appropiate [key size][1].
    ///
    /// [1]: constant.KEY_SIZE.html
    pub fn derive_key(&mut self, hash: &Sha256dHash) -> &mut Builder {
        let key0 = LittleEndian::read_u64(&hash[0..8]);
        let key1 = LittleEndian::read_u64(&hash[8..16]);
        self.key = (key0, key1);
        self
    }

    /// Sets the filter key.
    pub fn set_key(&mut self, key: (u64, u64)) -> &mut Builder {
        self.key = key;
        self
    }

    /// Sets the filter probability
    ///
    /// # Panics
    ///
    /// This function panics if P is larger than 32.
    pub fn set_p(&mut self, p: u8) -> &mut Builder {
        assert!(p <= 32, "P is too big");
        self.p = p;
        self
    }

    /// Reserve more space for filter entries.
    pub fn reserve(&mut self, n: usize) -> &mut Builder {
        self.data.reserve(n);
        self
    }

    /// Adds an entry to be included in the GCS filter when it's built.
    pub fn add_entry(&mut self, data: &[u8]) -> &mut Builder {
        self.data.push(data.to_vec());
        self
    }

    pub fn add_outpoint(&mut self, outpoint: &TxOutRef) -> &mut Builder {
        let txid = outpoint.txid.data();
        let index = outpoint.index as u32;

        let mut entry = [0u8; 32 + 4];
        (&mut entry[0..32]).copy_from_slice(&txid);
        LittleEndian::write_u32(&mut entry[32..36], index);

        self.add_entry(&entry);
        self
    }

    pub fn add_hash(&mut self, hash: &Sha256dHash) -> &mut Builder {
        let entry = hash.data();

        self.add_entry(&entry);
        self
    }

    // TODO: add_hash, add_script, add_witness.

    // Accessors

    /// Returns the key used by this builder, this is useful when the key is
    /// created with [`random_key`][1].
    ///
    /// [1]: #method.random_key
    pub fn key(&self) -> (u64, u64) {
        self.key
    }

    // Build function
    
    /// Builds the GCS filter.
    pub fn build(self) -> Filter {
        Filter::build(self.p, self.key, &self.data)
    }
}

pub fn build_basic_filter(block: &Block) -> Filter {
    let blockhash = block.bitcoin_hash();

    let mut builder = Builder::new();

    builder.set_p(DEFAULT_P);
	builder.derive_key(&blockhash);

    let mut n = 0;

    for (i, tx) in block.txdata.iter().enumerate() {
        n += 1;
 
		// Skip the inputs for the coinbase transaction
        if i != 0 {
            n += tx.input.iter().count();
        }

        n += tx.output.iter().count();
    }

    builder.reserve(n);

	// In order to build a basic filter, we'll range over the entire block,
	// adding the outpoint data as well as the data pushes within the
	// pkScript.
	for (i, tx) in block.txdata.iter().enumerate() {
		let txid = tx.txid();
		builder.add_hash(&txid);

		// Skip the inputs for the coinbase transaction
		if i != 0 {
			// Each each txin, we'll add a serialized version of
			// the txid:index to the filters data slices.
			for txin in tx.input.iter() {
                let outpoint = TxOutRef {
                    txid: txin.prev_hash.clone(),
                    index: txin.prev_index.clone() as usize,
                };

				builder.add_outpoint(&outpoint);
			}
		}

		// For each output in a transaction, we'll add each of the
		// individual data pushes within the script.
		for txout in tx.output.iter() {
            let data = txout.script_pubkey.data();

			builder.add_entry(data.as_slice());
		}
	}

    builder.build()
}
