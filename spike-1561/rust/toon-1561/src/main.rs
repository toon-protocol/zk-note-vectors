//! PROTOTYPE for toon-protocol/connector#1561 — throwaway.
use std::{path::PathBuf, time::Instant};
use ledger::proofs::toon1561::*;
use mina_curves::pasta::Fp;

fn main() -> anyhow::Result<()> {
    let dump = PathBuf::from(std::env::args().nth(1).expect("dump dir"));
    let t = Instant::now();
    let step = load_prover::<StepLand, Fp>(&dump, "cs003");
    eprintln!("step prover index built in {:?}", t.elapsed());
    let w = load_o1js_witness::<Fp>(&dump.join("w003_cs003.json"));
    eprintln!("witness: primary {} aux {}", 1, w.aux_len());
    match prove_step::<StepLand>(&step, &w, true) {
        Err(e) => eprintln!("constraint check: {e:#}"),
        Ok(_) => unreachable!(),
    }
    let t = Instant::now();
    let p = prove_step::<StepLand>(&step, &w, false)?;
    eprintln!("step proof made in {:?}; public input {:?}", t.elapsed(), p.public_input);
    Ok(())
}
