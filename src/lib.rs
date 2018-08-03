extern crate bitstream_io;
extern crate siphasher;

#[cfg(feature = "builder")]
extern crate byteorder;
#[cfg(any(feature = "builder", feature = "decode"))]
extern crate bitcoin;

#[cfg(feature = "builder")]
pub mod builder;

use std::io::{self, Cursor};
use std::hash::Hasher;

use bitstream_io::{BE, BitReader, BitWriter};
use siphasher::sip::SipHasher24;

/// Default collision probability (2<sup>-20</sup>).
pub const DEFAULT_P: u8 = 20;

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
    pub fn build(p: u8, key: (u64, u64), data: &Vec<Vec<u8>>) -> Filter {
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
            let v = siphash24(key, datum);
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

    #[cfg(feature = "decode")]
    pub fn from_nbytes(p: u8, data: &[u8]) -> Result<Filter, bitcoin::util::Error> {
        use bitcoin::network::encodable::{ConsensusDecodable, VarInt};
        use bitcoin::network::serialize::RawDecoder;
        use bitcoin::util::Error;

        let (n, pos) = {
            let mut cursor = Cursor::new(data);
            let mut decoder = RawDecoder::new(&mut cursor);
            let n = VarInt::consensus_decode(&mut decoder)?;
            (n.0, n.encoded_length() as usize)
        };

        if n >= u64::from(u32::max_value()) {
            return Err(Error::ParseFailed);
        }

        let filter = Filter::from_bytes(n as u32, p, (&data[pos..]).to_vec());
        Ok(filter)
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
    pub fn is_member(&self, key: (u64, u64), data: &[u8]) -> bool {
        let mut cursor = Cursor::new(&self.data);
        let mut bstream = BitReader::new(&mut cursor);

        // We hash our search term with the same parameters as the filter.
        let term = siphash24(key, data);
        let term = reduce(term, u64::from(self.p));

        // Go through the search filter and look for the desired value.
        let mut last_value = 0u64;
        while last_value < term {
            // Read the difference between previous and new value from
            // bitstream.
            let value = match read_full_u64(self, &mut bstream) {
                Ok(v) => v,
                // The kind is ErrorKind::UnexpectedEof
                Err(_) => return false,
            };

            // Add the previous value to it.
            let value = value + last_value;
            if value == term {
                return true;
            }

            last_value = value;
        }

        false
    }

    /// Checks whether any value is likely (within collision probability) to be a
    /// member of the set represented by the filter faster than calling
    /// [`is_member`][1] for each value individually.
    ///
    /// [1]: #method.is_member
    pub fn is_member_any(&self, key: (u64, u64), data: &Vec<Vec<u8>>) -> bool {
        let mut cursor = Cursor::new(&self.data);
        let mut bstream = BitReader::new(&mut cursor);

        // Create an uncompressed filter of the search values.
        let mut values = Vec::with_capacity(data.len());

        for datum in data.iter() {
            // For each datum, we assign the initial hash to a uint64.
            let v = siphash24(key, datum.as_slice());

            // We'll then reduce the value down to the range of our
            // modulus.
            let v = reduce(v, u64::from(self.p));
            values.push(v);
        }
        values.sort();

        // Zip down the filters, comparing values until we either run out of
        // values to compare in one of the filters or we reach a matching
        // value.
        let mut last_value = (0, values[0]);
        let mut i = 1;
        while last_value.0 != last_value.1 {
            // Check which filter to advance to make sure we're comparing
            // the right values.
            if last_value.0 > last_value.1 {
                // Advance filter created from search terms or return
                // false if we're at the end because nothing matched.
                if i < values.len() {
                    last_value.1 = values[i];
                    i += 1;
                } else {
                    return false;
                }
            } else if last_value.1 > last_value.0 {
                // Advance filter we're searching or return false if
                // we're at the end because nothing matched.
                let value = match read_full_u64(self, &mut bstream) {
                    Ok(v) => v,
                    // The kind is ErrorKind::UnexpectedEof
                    Err(_) => return false,
                };

                last_value.0 += value;
            }
        }

        // If we've made it this far, an element matched between filters so we
        // return true.
        true
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

/// Calculate SipHash 2-4
pub fn siphash24(key: (u64, u64), data: &[u8]) -> u64 {
    let mut hasher = SipHasher24::new_with_keys(key.0, key.1);
    hasher.write(data);
    hasher.finish()
}

/// Reads a value represented by the sum of a unary multiple of
/// the filter's P modulus (`2**P`) and a big-endian P-bit remainder.
fn read_full_u64(filter: &Filter, bstream: &mut BitReader<BE>) -> io::Result<u64> {
	let mut quotient = 0u64;

	// Count the 1s until we reach a 0.
	let c = bstream.read_bit()?;
	while c {
		quotient += 1;
	}

	// Read P bits.
	let remainder: u64 = bstream.read(u32::from(filter.p))?;

	// Add the multiple and the remainder.
	Ok((quotient << u64::from(filter.p)) + remainder)
}
