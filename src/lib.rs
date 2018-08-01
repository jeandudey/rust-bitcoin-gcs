extern crate bitcoin;
extern crate bitstream_io;
extern crate siphasher;

use std::collections::HashSet;
use std::hash::Hasher;

use bitcoin::util::hash::Sha256dHash;
use bitstream_io::BE;
use bitstream_io::write::BitWriter;
use siphasher::sip::SipHasher24;

pub const KEY_SIZE: usize = 16;
/// Default collision probability (2<sup>-20</sup>).
pub const DEFAULT_P: u8 = 20;

/// A GCS filter builder.
#[derive(Debug)]
pub struct Builder {
    p: u8,
    key: [u8; KEY_SIZE],
    data: HashSet<Vec<u8>>,
}

impl Builder {
    // Constructors

    /// Creates a new `Builder`.
    pub fn new() -> Builder {
        Builder {
            p: 0,
            key: [0u8; KEY_SIZE],
            data: HashSet::new(),
        }
    }

    // Building functions

    /// Generates a cryptographically secure random key to be used with the
    /// filter.
    pub fn random_key(&mut self) -> &mut Builder {
        panic!()
    }

    /// This functions derives a key from a `Sha256dHash` by truncating the
    /// bytes truncating the hash to the appropiate [key size][1].
    ///
    /// [1]: constant.KEY_SIZE.html
    pub fn derive_key(&mut self, hash: &Sha256dHash) -> &mut Builder {
        let bytes = hash.data();
        self.key.copy_from_slice(&bytes[0..KEY_SIZE]);
        self
    }

    /// Sets the filter key.
    pub fn set_key(&mut self, key: [u8; KEY_SIZE]) -> &mut Builder {
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

    /// Adds an entry to be included in the GCS filter when it's built.
    pub fn add_entry<D>(&mut self, data: &[u8]) -> &mut Builder {
        self.data.insert(data.to_vec());
        self
    }

    // TODO: add_outpoint, add_hash, add_script, add_witness.

    // Accessors

    /// Returns the key used by this builder, this is useful when the key is
    /// created with [`random_key`][1].
    ///
    /// [1]: #method.random_key
    pub fn key(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }

    // Build function
    
    /// Builds the GCS filter.
    pub fn build(self) -> Filter {
        let mut slices = Vec::with_capacity(self.data.len());
        for datum in self.data {
            slices.push(datum)
        }

        Filter::build(self.p, self.key, slices.as_slice())
    }
}

/// Describes a serialized Golomb Coded Set (GCS) filter.
#[derive(Debug, Clone)]
pub struct Filter {
    n: u32,
    p: u8,
    modulus_np: u64,
    data: Vec<u8>,
}

impl Filter {
    // Constructors

    /// Build a new `Filter` from the given data.
    ///
    /// # Panics
    ///
    /// If the set length is too big the function panics, also if the false
    /// positive rate is too big the function also panics.
    pub fn build(p: u8, _key: [u8; KEY_SIZE], data: &[Vec<u8>]) -> Filter {
        // Check that data.len() (N) isn't larger than a u32.
        assert!(data.len() <= u32::max_value() as usize, "N is too big");
        assert!(p <= 32, "P is too big");

        let mut filter = Filter {
            n: data.len() as u32,
            p,
            modulus_np: 0,
            data: Vec::new(),
        };

        filter.modulus_np = u64::from(filter.n) << filter.p;

        // Check if we need to do any work.
        if filter.is_empty() {
            return filter;
        }

        let mut values = Vec::with_capacity(filter.n as usize);
        for datum in data {
            let mut hasher = SipHasher24::new();
            hasher.write(datum.as_slice());
            let v = hasher.finish();
            let v = reduce(v, filter.modulus_np);
            values.push(v);
        }
        values.sort();

        // Write the sorted list of values into the filter bitstream,
        // compressing it using Golomb coding.
        let mut data: Vec<u8> = Vec::new();
        {
            let mut value: u64;
            let mut last_value = 0u64;
            let mut remainder: u64;
            let mut bstream: BitWriter<BE> = BitWriter::new(&mut data);
            for v in values.iter() {
                // Calculate the difference between this value and the last,
                // modulo P.
                remainder = (*v - last_value) & ((1u64 << u64::from(filter.p)) - 1);

                // Calculate the difference between this value and the last,
                // divided by P.
                value = (*v - last_value - remainder) >> u64::from(filter.p);
                last_value = *v;

                // Write the P multiple into the bitstream in unary; the
                // average should be around 1 (2 bits - 0b10).
                while value > 0 {
                    bstream.write_bit(true).unwrap();
                    value -= 1;
                }
                bstream.write_bit(false).unwrap();

                // Write the remainder as a big-endian integer with enough bits
                // to represent the appropriate collision probability.
                bstream.write(u32::from(filter.p), remainder).unwrap();
            }
        }

        filter.data = data;

        filter
    }

    /// Construct a `Filter` from a built set.
    pub fn from_bytes(n: u32, p: u8, data: Vec<u8>) -> Filter {
        assert!(p <= 32, "P is too big");

        Filter {
            n,
            p,
            modulus_np: u64::from(n) << p,
            data,
        }
    }

    // Accessors
    
    /// Returns the set length (N).
    pub fn n(&self) -> u32 { self.n }

    /// Returns the false positive rate (P).
    pub fn p(&self) -> u8 { self.p }

    /// Returns the serialized format of the filter.
    pub fn as_bytes(&self) -> &[u8] { self.data.as_slice() }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    // Set operations

    /// Checks whether a value is likely (within collision probability) to be a
    /// member of the set represented by the filter.
    pub fn is_member(&self, key: [u8; KEY_SIZE], _data: &[u8]) -> bool {
        unimplemented!()
    }

    /// Checks whether any value is likely (within collision probability) to be a
    /// member of the set represented by the filter faster than calling
    /// [`is_member`][1] for each value individually.
    ///
    /// [1]: #method.is_member
    pub fn is_member_any(key: [u8; KEY_SIZE], _data: &[Vec<u8>]) -> bool {
        unimplemented!()
    }
}

/// Calculate a mapping that is more or less equivalent to x mod N.
///
/// Instead of using a mod operation, which using a non-power-of-two will lead
/// to slowness on many processors due to unnecesary division, we instead use a
/// "multiply- and-shift" trick which eliminates all division described in [*A
/// fast alternative to the modulo reduction*][1].
///  
/// (x * N) >> log<sub>2(N)</sub>
///
/// Where log<sub>2</sub> is 64.
///
/// [1]: https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
pub fn reduce(x: u64, n: u64) -> u64 {
    ((u128::from(x) * u128::from(n)) >> 64) as u64
}
