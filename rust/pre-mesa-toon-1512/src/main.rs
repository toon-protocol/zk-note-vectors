//! toon-protocol/connector#1512: verify o1js ZkProgram proofs in Rust, and
//! check Rust Poseidon, hash-to-curve and Schnorr against o1js vectors.
//!
//! Usage: toon-1512 <fixtures-dir>   (spend.json, wrap.json, parity.json)

use std::{str::FromStr, time::Instant};

use ark_ff::{BigInteger, PrimeField};

use base64::Engine as _;
use groupmap::GroupMap;
use ledger::{
    proofs::{
        verification::{verify_sideloaded, verify_sideloaded_with_index},
        verifiers::make_zkapp_verifier_index,
        witness::Witness,
    },
    verifier::get_srs,
    VerificationKey,
};
use mina_curves::pasta::{Fp, Fq, PallasParameters};
use mina_hasher::{Hashable, Hasher, ROInput};
use mina_p2p_messages::{
    binprot::BinProtRead,
    v2::{
        MinaBaseVerificationKeyWireStableV1, PicklesProofProofsVerified2ReprStableV2,
        PicklesProofProofsVerifiedMaxStableV2,
    },
};
use mina_signer::{Keypair, NetworkId, SecKey, Signer};
use serde_json::Value;

fn fp(v: &Value) -> Fp {
    Fp::from_str(v.as_str().unwrap()).unwrap()
}

fn fq(v: &Value) -> Fq {
    Fq::from_str(v.as_str().unwrap()).unwrap()
}

fn fields(v: &Value) -> Vec<Fp> {
    v.as_array().unwrap().iter().map(fp).collect()
}

fn dec(f: impl PrimeField) -> String {
    f.into_bigint().to_string()
}

// ---- Proofs ----------------------------------------------------------------

fn load_vk(b64: &str) -> VerificationKey {
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
    let mut slice = bytes.as_slice();
    let wire = MinaBaseVerificationKeyWireStableV1::binprot_read(&mut slice).unwrap();
    assert!(slice.is_empty(), "trailing bytes after the verification key");
    VerificationKey::try_from(&wire).unwrap()
}

/// o1js writes a proof at its own `maxProofsVerified`; a side-loaded verifier
/// reads it at the maximum, 2. Pickles' `Wrap_hack.pad_proof` front-extends
/// `messages_for_next_wrap_proof.old_bulletproof_challenges` to length 2 with
/// `Dummy.Ipa.Wrap.challenges`; the step-side lists stay as they are.
fn pad_proof(sexp: &mut rsexp::Sexp) {
    use rsexp::Sexp;
    fn field<'a>(record: &'a mut Sexp, name: &str) -> &'a mut Sexp {
        let Sexp::List(fields) = record else { panic!("not a record") };
        for f in fields.iter_mut() {
            if let Sexp::List(pair) = f {
                if matches!(&pair[0], Sexp::Atom(a) if a == name.as_bytes()) {
                    return &mut pair[1];
                }
            }
        }
        panic!("no field {name}")
    }
    let chals = field(
        field(field(field(sexp, "statement"), "proof_state"), "messages_for_next_wrap_proof"),
        "old_bulletproof_challenges",
    );
    let Sexp::List(chals) = chals else { panic!("not a list") };
    // Written by hand: this crate's `SexpOf` for a hex64 limb emits `0x…`,
    // which its own `OfSexp` refuses; OCaml writes 16 bare hex digits.
    let atom = |s: &str| Sexp::Atom(s.as_bytes().to_vec());
    let pair = |name: &str, v: Sexp| Sexp::List(vec![atom(name), v]);
    let dummy = Sexp::List(
        ledger::proofs::unfinalized::dummy_ipa_wrap_challenges()
            .iter()
            .map(|[a, b]| {
                let inner = Sexp::List(vec![atom(&format!("{a:016x}")), atom(&format!("{b:016x}"))]);
                Sexp::List(vec![pair("prechallenge", Sexp::List(vec![pair("inner", inner)]))])
            })
            .collect(),
    );
    while chals.len() < 2 {
        chals.insert(0, dummy.clone());
    }
}

fn load_proof(b64: &str) -> PicklesProofProofsVerified2ReprStableV2 {
    use rsexp::OfSexp;
    let bytes = base64::engine::general_purpose::URL_SAFE.decode(b64).unwrap();
    let mut sexp = rsexp::from_slice(&bytes).unwrap();
    pad_proof(&mut sexp);
    let max = PicklesProofProofsVerifiedMaxStableV2::of_sexp(&sexp).unwrap();
    (&max).into()
}

fn check_proof(path: &str, ok: &mut bool) {
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let name = fixture["program"].as_str().unwrap();
    let vk = load_vk(fixture["verificationKey"]["data"].as_str().unwrap());
    let vk_hash_matches = dec(vk.hash()) == fixture["verificationKey"]["hash"].as_str().unwrap();
    let proof = load_proof(fixture["proof"].as_str().unwrap());
    let mut public = fields(&fixture["publicInputFields"]);
    public.extend(fields(&fixture["publicOutputFields"]));

    let srs = get_srs::<Fp>();
    let t = Instant::now();
    let good = verify_sideloaded(&vk, &public, &proof, &srs);
    let first = t.elapsed();

    if !good {
        println!("{name}: maxProofsVerified={} verifies=false vk_hash_matches_o1js={vk_hash_matches}", fixture["maxProofsVerified"]);
        *ok = false;
        return;
    }
    let runs = 20;
    let t = Instant::now();
    for _ in 0..runs {
        assert!(verify_sideloaded(&vk, &public, &proof, &srs));
    }
    let warm = t.elapsed() / runs;

    let t = Instant::now();
    let index = make_zkapp_verifier_index(&vk);
    let index_build = t.elapsed();
    let t = Instant::now();
    for _ in 0..runs {
        assert!(verify_sideloaded_with_index(&vk, &index, &public, &proof, &srs));
    }
    let cached = t.elapsed() / runs;

    // The same proof against a public input with one field changed.
    let mut tampered = public.clone();
    tampered[0] += Fp::from(1u64);
    let rejects_tampered = !verify_sideloaded(&vk, &tampered, &proof, &srs);

    // The same proof against a public input that is one field short.
    let rejects_short = !verify_sideloaded(&vk, &public[..public.len() - 1], &proof, &srs);

    println!(
        "{name}: maxProofsVerified={} public_fields={} verifies={good} vk_hash_matches_o1js={vk_hash_matches} \
         rejects_tampered_input={rejects_tampered} rejects_short_input={rejects_short} \
         first_verify={first:?} warm_verify_mean_of_{runs}={warm:?} \
         index_build={index_build:?} verify_with_cached_index_mean_of_{runs}={cached:?}",
        fixture["maxProofsVerified"],
        public.len(),
    );
    *ok &= good && vk_hash_matches && rejects_tampered && rejects_short;
}

fn check_cross(spend: &str, wrap: &str, ok: &mut bool) {
    // A proof is refused under another program's verification key.
    let spend: Value = serde_json::from_str(&std::fs::read_to_string(spend).unwrap()).unwrap();
    let wrap: Value = serde_json::from_str(&std::fs::read_to_string(wrap).unwrap()).unwrap();
    let vk = load_vk(wrap["verificationKey"]["data"].as_str().unwrap());
    let proof = load_proof(spend["proof"].as_str().unwrap());
    let public = fields(&spend["publicInputFields"]);
    let refused = !verify_sideloaded(&vk, &public, &proof, &get_srs::<Fp>());
    println!("cross: spend proof under wrap vk refused={refused}");
    *ok &= refused;
}

// ---- Parity ----------------------------------------------------------------

#[derive(Clone)]
struct Prefix(Option<String>);

impl mina_hasher::DomainParameter for Prefix {
    fn into_bytes(self) -> Vec<u8> {
        vec![]
    }
}

#[derive(Clone)]
struct Fields(Vec<Fp>);

impl Hashable for Fields {
    type D = Prefix;

    fn to_roinput(&self) -> ROInput {
        self.0.iter().fold(ROInput::new(), |r, f| r.append_field(*f))
    }

    fn domain_string(prefix: Self::D) -> Option<String> {
        prefix.0
    }
}

#[derive(Clone)]
struct Message(Vec<Fp>);

impl Hashable for Message {
    type D = NetworkId;

    fn to_roinput(&self) -> ROInput {
        self.0.iter().fold(ROInput::new(), |r, f| r.append_field(*f))
    }

    fn domain_string(network: NetworkId) -> Option<String> {
        Some(
            match network {
                NetworkId::MAINNET => "MinaSignatureMainnet",
                NetworkId::TESTNET => "CodaSignature*******",
            }
            .into(),
        )
    }
}

fn poseidon(input: &[Fp], prefix: Option<&str>) -> Fp {
    let mut h = mina_hasher::create_kimchi::<Fields>(Prefix(prefix.map(str::to_owned)));
    h.hash(&Fields(input.to_vec()))
}

fn tally(label: &str, results: impl IntoIterator<Item = bool>, ok: &mut bool) {
    let results: Vec<bool> = results.into_iter().collect();
    let pass = results.iter().filter(|r| **r).count();
    println!("{label}: {pass}/{} byte-identical", results.len());
    *ok &= pass == results.len();
}

fn check_parity(path: &str, ok: &mut bool) {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();

    tally(
        "poseidon.hash",
        v["poseidon"].as_array().unwrap().iter().map(|c| {
            let got = poseidon(&fields(&c["input"]), None);
            let pass = got == fp(&c["output"]);
            if !pass {
                println!("  input {} -> rust {}, o1js {}", c["input"], dec(got), c["output"]);
            }
            pass
        }),
        ok,
    );

    tally(
        "poseidon.hashWithPrefix",
        v["hashWithPrefix"].as_array().unwrap().iter().map(|c| {
            poseidon(&fields(&c["input"]), c["prefix"].as_str()) == fp(&c["output"])
        }),
        ok,
    );

    // o1js maps with Snarky's conic (SvdW) group map, which mina-rust ports
    // in-circuit; proof-systems' `groupmap` BW19 is the IPA's map, not this one.
    let bw19 = groupmap::BWParameters::<PallasParameters>::setup();
    let mut bw19_matches = 0;
    tally(
        "poseidon.hashToGroup (mina-rust conic map)",
        v["hashToGroup"].as_array().unwrap().iter().map(|c| {
            let digest = poseidon(&fields(&c["input"]), None);
            let g = ledger::proofs::group_map::to_group(digest, &mut Witness::empty());
            let (x, mut y) = (g.x, g.y);
            if y.into_bigint().is_odd() {
                y = -y;
            }
            let (bx, _) = bw19.to_group(digest);
            if bx == fp(&c["x"]) {
                bw19_matches += 1;
            }
            x == fp(&c["x"]) && y == fp(&c["y"])
        }),
        ok,
    );
    println!("poseidon.hashToGroup via proof-systems groupmap BW19 (informational): {bw19_matches} x-coordinates match");

    let sign = |network: NetworkId, c: &Value| {
        let sk = SecKey::new(fq(&c["privateKey"]));
        let kp = Keypair::from_secret_key(sk).unwrap();
        let address_matches = kp.public.into_address() == c["publicKeyBase58"].as_str().unwrap();
        let mut signer = mina_signer::create_kimchi::<Message>(network);
        let msg = Message(fields(&c["message"]));
        let same = |sig: mina_signer::Signature| sig.rx == fp(&c["r"]) && sig.s == fq(&c["s"]);
        let identical = (same(signer.sign(&kp, &msg, true)), same(signer.sign(&kp, &msg, false)));
        // Even where the nonce differs, the o1js signature must verify in Rust.
        let theirs = mina_signer::Signature::new(fp(&c["r"]), fq(&c["s"]));
        let verifies = signer.verify(&theirs, &kp.public, &Message(fields(&c["message"])));
        (address_matches, identical, verifies)
    };

    for (label, vectors) in [
        ("schnorr Signature.create (devnet)", &v["schnorr"]["provable"]),
        ("schnorr mina-signer", &v["schnorr"]["minaSigner"]),
    ] {
        let results: Vec<_> = vectors
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                let network = match c["network"].as_str() {
                    Some("mainnet") => NetworkId::MAINNET,
                    _ => NetworkId::TESTNET,
                };
                sign(network, c)
            })
            .collect();
        tally(&format!("{label} address"), results.iter().map(|r| r.0), ok);
        tally(&format!("{label} signature, packed nonce"), results.iter().map(|r| r.1 .0), ok);
        let unpacked = results.iter().filter(|r| r.1 .1).count();
        println!("{label} signature, unpacked nonce (informational): {unpacked}/{} byte-identical", results.len());
        tally(&format!("{label} o1js signature verifies in rust"), results.iter().map(|r| r.2), ok);
    }
}

fn main() {
    let dir = std::env::args().nth(1).expect("usage: toon-1512 <fixtures-dir>");
    let mut ok = true;
    let t = Instant::now();
    let _ = get_srs::<Fp>();
    println!("srs: created in {:?}", t.elapsed());
    check_proof(&format!("{dir}/spend.json"), &mut ok);
    check_proof(&format!("{dir}/wrap.json"), &mut ok);
    check_cross(&format!("{dir}/spend.json"), &format!("{dir}/wrap.json"), &mut ok);
    check_parity(&format!("{dir}/parity.json"), &mut ok);
    println!("{}", if ok { "ALL PASS" } else { "FAILURES" });
    std::process::exit(if ok { 0 } else { 1 });
}
