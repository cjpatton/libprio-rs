// SPDX-License-Identifier: MPL-2.0

//! Implementation of the Prio protocol.
//!
//! TODO: Decide how to authenticate the leader in leader<->helper communication.
//!
//! TODO: Maybe add support for more PRNGs. (ChaCha20 may be preferable over AES128-GCM for WASM.
//! See:
//! * https://00f.net/2019/10/22/updated-webassembly-benchmark/
//! * https://github.com/jedisct1/libsodium/tree/master/test/default

use crate::field::{FieldElement, FieldError};
use crate::pcp::gadgets::MeanVarUnsigned as Mvu;
use crate::pcp::types::{MeanVarUnsignedVector as MvuVec, TypeError};
use crate::pcp::{decide, prove, query, Gadget, PcpError, Proof, Value, Verifier};
use crate::prng::Prng;

use hpke::aead::ExportOnlyAead;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::kex::KeyExchange;
use hpke::{EncappedKey, HpkeError, Kem as KemTrait, OpModeR, OpModeS};

use std::convert::TryFrom;
use std::marker::PhantomData;

type Kem = X25519HkdfSha256;
type Kex = <Kem as KemTrait>::Kex;

/// An HPKE public key.
pub struct HpkePublicKey {
    // XXX
}

/// An HPKE secret key.
pub struct HpkeSecretKey {
    // XXX
}

/// Code points for pseudorandom generators used for deriving pseudorandom field elements.
#[derive(Clone, Copy)]
pub enum PAPrng {
    /// AES-128 in CTR mode. The seed is 32 bytes long: the first 16 are used as the key; and last
    /// 16 are used as the IV.
    Aes128Ctr,
}

/// The seed length for PRNG operations. This is hard-coded for now because there is only one PRNG
/// in use.
const SEED_LEN: usize = 32;

/// Code points for finite fields.
pub enum PAField {
    /// The 64-bit field implemented by `prio::field::Field64`.
    Field64,
}

/// Parameters for the Prio protocol.
pub struct PrioParam {
    /// The type of data being collected.
    pub data_type: PrioDataType,

    /// The field used to encode client inputs.
    pub field: PAField,

    /// The PRG used to generate pseudorandom field elements.
    pub prng: PAPrng,
}

/// Data types.
pub enum PrioDataType {
    /// Corresponds to `prio;:pcp::types::MvuVec`.
    MvuVec {
        /// Length in bits of each integer in the vector.
        bits: usize,
        /// Length of the vector.
        length: usize,
    },
}

/// Errors emitted by the message processors.
#[derive(Debug, thiserror::Error)]
pub enum PrioError {
    /// A message processor was called with a PRG seed of unexpected length.
    #[error("unexpected seed length")]
    UnexpectedSeedLen,

    /// XXX A catch all for error I haven't thought through.
    #[error("todo error")]
    Todo(&'static str),

    /// Encountered an error when generating or verifying a proof
    #[error("PCP error")]
    Pcp(#[from] PcpError),

    #[error("Field error")]
    Field(#[from] FieldError),

    #[error("Type error")]
    Type(#[from] TypeError),
}

impl From<HpkeError> for PrioError {
    fn from(err: HpkeError) -> Self {
        panic!("XXX: Unhandled HpkeError: {}", err);
    }
}

const INFO_STR: &'static [u8] = b"XXX: This should be the serialized PATask";
const SHARE_INFO_STR: &'static [u8] = b"XXX Thsi should be some fixed string";

// XXX Rename this to `PrioUploadParam` or something.
pub struct PrioClientParam {
    joint_rand_seed: Vec<u8>,
}

pub struct PrioLeaderShare {
    pub input: Vec<u8>,
    pub proof: Vec<u8>,
}

pub struct PrioHelperShare {
    pub enc: EncappedKey<Kex>,
    pub input_len: usize,
    pub proof_len: usize,
}

pub struct PrioVerifyReq {
    query_rand_seed: Vec<u8>,
    joint_rand_seed: Vec<u8>,
    leader_verifier_share: Vec<u8>,
}

pub struct PrioVerifyResp {
    helper_verifier_share: Vec<u8>,
}

/// XXX
pub fn client_upload<F, G, V>(
    input: &V,
    client_param: &PrioClientParam,
    pk: &<Kex as KeyExchange>::PublicKey,
    param: &PrioParam,
) -> Result<(PrioLeaderShare, PrioHelperShare), PrioError>
where
    F: FieldElement,
    G: Gadget<F>,
    V: Value<F, G>,
{
    // Generate the proof.
    let joint_rand = derive_joint_rand(&client_param.joint_rand_seed, input.valid_rand_len());
    let proof = prove(input, &joint_rand)?;

    // Generate the HPKE context shared with the helper.
    let mut rng = rand::thread_rng();
    let (enc, ctx) = hpke::setup_sender::<ExportOnlyAead, HkdfSha256, Kem, _>(
        &OpModeS::Base,
        pk,
        INFO_STR,
        &mut rng,
    )?;

    // Compute the helper's share.
    let mut share_seed: Vec<u8> = vec![0; SEED_LEN];
    ctx.export(SHARE_INFO_STR, &mut share_seed)?;
    let mut it = Prng::new(&share_seed, input.as_slice().len() + proof.as_slice().len());

    // Compute the leader's share.
    let mut raw_input_share: Vec<u8> = Vec::with_capacity(input.as_slice().len() * F::BYTES);
    for &x in input.as_slice() {
        let s = x - it.next().unwrap();
        s.append_to(&mut raw_input_share);
    }

    let mut raw_proof_share: Vec<u8> = Vec::with_capacity(proof.as_slice().len() * F::BYTES);
    for &x in proof.as_slice() {
        let s = x - it.next().unwrap();
        s.append_to(&mut raw_proof_share);
    }

    Ok((
        PrioLeaderShare {
            input: raw_input_share,
            proof: raw_proof_share,
        },
        PrioHelperShare {
            enc,
            input_len: input.as_slice().len(),
            proof_len: proof.as_slice().len(),
        },
    ))
}

pub struct PrioLeader<F, G, V>
where
    F: FieldElement,
    G: Gadget<F>,
    V: Value<F, G>,
{
    phantom: PhantomData<G>,
    input_share: V,
    proof_share: Proof<F>,
    verifier_share: Option<Verifier<F>>,
}

impl<F, G, V> PrioLeader<F, G, V>
where
    F: FieldElement,
    G: Gadget<F>,
    V: Value<F, G>,
{
    fn new(leader_share: &PrioLeaderShare, param: V::Param) -> Result<Self, PrioError> {
        let mut input_share = V::try_from((param, read_vec(&leader_share.input)?))?;
        let proof_share = Proof::from(read_vec(&leader_share.proof)?);
        input_share.set_leader(true);

        Ok(PrioLeader {
            phantom: PhantomData,
            input_share,
            proof_share,
            verifier_share: None, // Not known until verify_start
        })
    }

    /// Produces the verify request.
    fn verify_start(&mut self, client_param: &PrioClientParam) -> Result<PrioVerifyReq, PrioError> {
        let query_rand_seed: Vec<u8> = (0..SEED_LEN).map(|_| rand::random::<u8>()).collect();
        let (verifier_share, raw_verifier_share) = do_query(
            &self.input_share,
            &self.proof_share,
            &query_rand_seed,
            &client_param.joint_rand_seed,
        )?;

        self.verifier_share = Some(verifier_share);
        Ok(PrioVerifyReq {
            query_rand_seed,
            joint_rand_seed: client_param.joint_rand_seed.clone(),
            leader_verifier_share: raw_verifier_share,
        })
    }

    /// Consumes the verify response sent by the helper. If the input is valid, then this call
    /// returns the leader's share of the aggreg
    fn verify_finish<'a>(&'a self, resp: &PrioVerifyResp) -> Result<&'a V, PrioError> {
        let leader_verifier_share = self.verifier_share.as_ref().unwrap(); // call verify_start() first
        let helper_verifier_share = Verifier::from(read_vec(&resp.helper_verifier_share)?);

        let verifier = Verifier::from(sum_vec(
            leader_verifier_share.as_slice(),
            helper_verifier_share.as_slice(),
        )?);

        if !decide(&self.input_share, &verifier)? {
            return Err(PrioError::Todo("input is invalid!"));
        }
        Ok(&self.input_share)
    }
}

// Message processor for the helper.
pub struct PrioHelper<F, G, V>
where
    F: FieldElement,
    G: Gadget<F>,
    V: Value<F, G>,
{
    phantom: PhantomData<G>,
    input_share: V,
    proof_share: Proof<F>,
    verifier_share: Option<Verifier<F>>,
    peer_verifier_share: Option<Verifier<F>>,
}

impl<F, G, V> PrioHelper<F, G, V>
where
    F: FieldElement,
    G: Gadget<F>,
    V: Value<F, G>,
{
    fn new(
        helper_share: &PrioHelperShare,
        sk: &<Kex as KeyExchange>::PrivateKey,
        param: V::Param,
    ) -> Result<Self, PrioError>
    where
        G: Gadget<F>,
        V: Value<F, G>,
    {
        // Derive the HPKE context shared with the client.
        let ctx = hpke::setup_receiver::<ExportOnlyAead, HkdfSha256, Kem>(
            &OpModeR::Base,
            sk,
            &helper_share.enc,
            INFO_STR,
        )?;

        // Compute the helper's share.
        let mut share_seed: Vec<u8> = vec![0; SEED_LEN];
        ctx.export(SHARE_INFO_STR, &mut share_seed)?;
        let mut it: Prng<F> =
            Prng::new(&share_seed, helper_share.proof_len + helper_share.input_len);

        let mut input_share_data = Vec::with_capacity(helper_share.input_len);
        for _ in 0..helper_share.input_len {
            input_share_data.push(it.next().unwrap());
        }

        let mut proof_share_data = Vec::with_capacity(helper_share.proof_len);
        for _ in 0..helper_share.proof_len {
            proof_share_data.push(it.next().unwrap());
        }

        let mut input_share = V::try_from((param, input_share_data))?;
        let proof_share = Proof::from(proof_share_data);
        input_share.set_leader(false);

        Ok(Self {
            phantom: PhantomData,
            input_share,
            proof_share,
            verifier_share: None,      // Not known until verify_start
            peer_verifier_share: None, // Not known until verify_start
        })
    }

    // Consumes the verify request and produces the verify response.
    fn verify_start(&mut self, req: &PrioVerifyReq) -> Result<PrioVerifyResp, PrioError> {
        let (verifier_share, raw_verifier_share) = do_query(
            &self.input_share,
            &self.proof_share,
            &req.query_rand_seed,
            &req.joint_rand_seed,
        )?;

        self.verifier_share = Some(verifier_share);
        self.peer_verifier_share = Some(Verifier::from(read_vec(&req.leader_verifier_share)?));
        Ok(PrioVerifyResp {
            helper_verifier_share: raw_verifier_share,
        })
    }

    // Returns the input if it was deemed valid.
    fn verify_finish<'a>(&'a self) -> Result<&'a V, PrioError> {
        let leader_verifier_share = self.peer_verifier_share.as_ref().unwrap(); // call verify_start() first
        let helper_verifier_share = self.verifier_share.as_ref().unwrap(); // call verify_start() first

        let verifier = Verifier::from(sum_vec(
            leader_verifier_share.as_slice(),
            helper_verifier_share.as_slice(),
        )?);

        if !decide(&self.input_share, &verifier)? {
            return Err(PrioError::Todo("input is invalid!"));
        }
        Ok(&self.input_share)
    }
}

fn do_query<F, G, V>(
    input: &V,
    proof: &Proof<F>,
    query_rand_seed: &[u8],
    joint_rand_seed: &[u8],
) -> Result<(Verifier<F>, Vec<u8>), PrioError>
where
    F: FieldElement,
    G: Gadget<F>,
    V: Value<F, G>,
{
    // Query the proof and input.
    let query_rand: Vec<F> = Prng::new(&joint_rand_seed, 1).collect();
    let joint_rand = derive_joint_rand(&joint_rand_seed, input.valid_rand_len());
    let verifier = query(input, proof, &query_rand, &joint_rand)?;

    // Encode the verifier.
    let mut raw_verifier = Vec::with_capacity(verifier.as_slice().len() * F::BYTES);
    for &x in verifier.as_slice() {
        x.append_to(&mut raw_verifier);
    }

    Ok((verifier, raw_verifier))
}

fn derive_joint_rand<F: FieldElement>(joint_rand_seed: &[u8], length: usize) -> Vec<F> {
    if joint_rand_seed.len() == 0 {
        return vec![];
    }

    Prng::new(&joint_rand_seed, length).collect()
}

fn read_vec<F: FieldElement>(raw_data: &[u8]) -> Result<Vec<F>, PrioError> {
    let mut data = Vec::with_capacity(raw_data.len() / F::BYTES);
    for chunk in raw_data.chunks(F::BYTES) {
        data.push(F::read_from(chunk)?);
    }
    Ok(data)
}

fn sum_vec<F: FieldElement>(x: &[F], y: &[F]) -> Result<Vec<F>, PrioError> {
    if x.len() != y.len() {
        return Err(PrioError::Todo("vector length mismatch"));
    }
    let mut outp = Vec::with_capacity(x.len());
    for i in 0..x.len() {
        outp.push(x[i] + y[i]);
    }

    Ok(outp)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::field::Field64 as F;

    use hpke::kdf::HkdfSha256;
    use hpke::kem::X25519HkdfSha256;

    use rand::SeedableRng;

    #[test]
    fn test_upload_verify() {
        // The helper picks its HPKE key pair.
        let mut rng = rand::thread_rng();
        let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut rng);

        // The collector picks the Prio parameters.
        let bits = 12;
        let length = 8;
        let param = PrioParam {
            data_type: PrioDataType::MvuVec { bits, length },
            field: PAField::Field64,
            prng: PAPrng::Aes128Ctr,
        };

        // The client encodes its measurement.
        let measurement = [23, 42, 99, 0, 1, 2, 6, 1337];
        let inp: MvuVec<F> = MvuVec::new(bits, &measurement).unwrap();

        // Upload Start: The leader responds to an upload start request by sending the client a
        // string called `joint_rand_seed`. The aggregators will use this string to verify the
        // proof.i
        let client_param = PrioClientParam {
            joint_rand_seed: (0..SEED_LEN).map(|_| rand::random::<u8>()).collect(),
        };

        // Upload Finish: The client generates `(leader_share, helper_share)` and uploads them to
        // the leader. (This computation uses `joint_rand_seed`.)
        let (leader_share, helper_share) = client_upload(&inp, &client_param, &pk, &param).unwrap();

        // Verify Finish (we don't need to do Verify Start): The leader sends its verifier share to
        // the helper. The helper responds with its verifier share and decides if the input is
        // valid. Finally, the leader decides if the input is valid.
        //
        // Leader -> helper
        let mut leader: PrioLeader<F, Mvu<F>, MvuVec<F>> =
            PrioLeader::new(&leader_share, bits).unwrap();
        let verify_req = leader.verify_start(&client_param).unwrap();

        // Helper -> leader
        let mut helper: PrioHelper<F, Mvu<F>, MvuVec<F>> =
            PrioHelper::new(&helper_share, &sk, bits).unwrap();
        let verify_resp = helper.verify_start(&verify_req).unwrap();
        let helper_input = helper.verify_finish().unwrap();

        // Leader
        let leader_input = leader.verify_finish(&verify_resp).unwrap();

        // Make sure the leader and helper have a secret sharing of the measurement.
        let data = sum_vec(leader_input.as_slice(), helper_input.as_slice()).unwrap();
        for (i, chunk) in data.chunks(bits + 2).enumerate() {
            let x = measurement[i];
            assert_eq!(x, u64::from(chunk[bits]));
            assert_eq!(x * x, u64::from(chunk[bits + 1]));
        }
    }
}
