// E4 in-process role verification benchmark (no IPC -> true crypto cost).
//
// Validates the verification-cost model (formalization §6.3):
//   verify-all  T = (t-k)*v_C + k*v_H,   v_H = v_C + v_Q
//   short-circuit stops after t valid signatures (with m=t it equals
//   verify-all; the m=n full-signing case shows the gap between the two).
// Also records the FN-DSA variable signature-length distribution.
//
// Usage: rolebench [out_dir] [iters]
use std::env;
use std::fs;
use std::time::Instant;

use ed25519_dalek::{Signer, SigningKey, Verifier};
use rand::rngs::OsRng;

fn quantile(xs: &mut [u128], q: f64) -> u128 {
    xs.sort_unstable();
    let i = ((xs.len() as f64 - 1.0) * q).round() as usize;
    xs[i.min(xs.len() - 1)]
}
struct Stat { med: f64, p25: f64, p75: f64 }
fn stat(xs: &mut [u128]) -> Stat {
    let us = |ns: u128| ns as f64 / 1000.0;
    Stat { med: us(quantile(xs, 0.5)), p25: us(quantile(xs, 0.25)), p75: us(quantile(xs, 0.75)) }
}

const MSG: &[u8] = b"role-canonical-metadata";
const TAU_C: &[u8] = b"PQTUF-v1|hyb:ed25519:pq|C|";

fn ed_key() -> (SigningKey, ed25519_dalek::VerifyingKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();
    (sk, pk)
}

fn ed_verify_stat(iters: usize) -> Stat {
    let (sk, pk) = ed_key();
    let s = sk.sign(MSG);
    pk.verify(MSG, &s).unwrap();
    let mut xs = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        pk.verify(MSG, &s).unwrap();
        xs.push(t.elapsed().as_nanos());
    }
    stat(&mut xs)
}

// Build n_ed classical and n_hyb hybrid signers, each signing the fixed MSG.
// Hybrid entry: (ed verifying key, ed signature, PQ public-key bytes, PQ sig obj)
macro_rules! build_set {
    ($mod:path, $tau_q:expr, $n_ed:expr, $n_hyb:expr) => {{
        use $mod::{detached_sign, keypair, DetachedSignature};
        use pqcrypto_traits::sign::{DetachedSignature as DS, PublicKey as PK};
        let mut ed: Vec<(ed25519_dalek::VerifyingKey, ed25519_dalek::Signature)> = Vec::new();
        let mut hyb = Vec::new();
        let cm = [TAU_C, MSG].concat();
        let qm = [$tau_q, MSG].concat();
        for _ in 0..$n_ed {
            let (sk, pk) = ed_key();
            let sig = sk.sign(&cm);
            ed.push((pk, sig));
        }
        for _ in 0..$n_hyb {
            let (esk, epk) = ed_key();
            let esig = esk.sign(&cm);
            let (qpk, qsk) = keypair();
            let qd = detached_sign(&qm, &qsk);
            let qobj = DetachedSignature::from_bytes(&qd.as_bytes()).unwrap();
            hyb.push((epk, esig, qpk.as_bytes().to_vec(), qobj, qm.clone()));
        }
        (ed, hyb, cm, qm)
    }};
}

macro_rules! verify_hyb {
    ($mod:path, $epk:expr, $esig:expr, $qpkbytes:expr, $qobj:expr, $cm:expr, $qm:expr) => {{
        use $mod::{verify_detached_signature, PublicKey};
        use pqcrypto_traits::sign::PublicKey as PK;
        $epk.verify($cm, $esig).unwrap();
        let qpk = PublicKey::from_bytes($qpkbytes).unwrap();
        verify_detached_signature($qobj, $qm, &qpk).unwrap();
    }};
}

macro_rules! pq_verify_stat {
    ($mod:path, $iters:expr) => {{
        use $mod::{detached_sign, keypair, verify_detached_signature, DetachedSignature};
        use pqcrypto_traits::sign::{DetachedSignature as DS, PublicKey as PK};
        let (pk, sk) = keypair();
        let d = detached_sign(MSG, &sk);
        let dobj = DetachedSignature::from_bytes(&d.as_bytes()).unwrap();
        verify_detached_signature(&dobj, MSG, &pk).unwrap();
        let mut xs = Vec::with_capacity($iters);
        for _ in 0..$iters {
            let t = Instant::now();
            verify_detached_signature(&dobj, MSG, &pk).unwrap();
            xs.push(t.elapsed().as_nanos());
        }
        stat(&mut xs)
    }};
}

// verify-all grid for a PQ module; also m=n short-circuit vs verify-all
macro_rules! role_grid {
    ($mod:path, $label:literal, $tau_q:expr, $w:expr, $iters:expr, $ed:expr, $pq:expr) => {{
        let t = 5usize;
        // m = t threshold release, verify-all
        for k in 0..=t {
            let (edv, hyb, cm, qm) = build_set!($mod, $tau_q, t - k, k);
            let mut xs = Vec::with_capacity($iters);
            for _ in 0..$iters {
                let t0 = Instant::now();
                for (epk, esig) in edv.iter() { epk.verify(&cm, esig).unwrap(); }
                for (epk, esig, qb, qo, qm2) in hyb.iter() {
                    verify_hyb!($mod, epk, esig, qb, qo, &cm, qm2);
                }
                xs.push(t0.elapsed().as_nanos());
            }
            let s = stat(&mut xs);
            let pred = (t - k) as f64 * $ed.med + k as f64 * ($ed.med + $pq.med);
            $w.push_str(&format!("{},{},{},{},verifyall,{:.3},{:.3},{:.3},{:.3},{:.3}\n",
                $label, t, k, t, s.p25, s.med, s.p75, pred, s.med - pred));
        }
        // m = n = t+2 full signing: verify-all(n) vs short-circuit(t)
        let n = t + 2;
        for k in 0..=t {
            let (edv, hyb, cm, qm) = build_set!($mod, $tau_q, n - k, k);
            let mut xa = Vec::with_capacity($iters);
            for _ in 0..$iters {
                let t0 = Instant::now();
                for (epk, esig) in edv.iter() { epk.verify(&cm, esig).unwrap(); }
                for (epk, esig, qb, qo, qm2) in hyb.iter() {
                    verify_hyb!($mod, epk, esig, qb, qo, &cm, qm2);
                }
                xa.push(t0.elapsed().as_nanos());
            }
            let sa = stat(&mut xa);
            let mut xs = Vec::with_capacity($iters);
            for _ in 0..$iters {
                let t0 = Instant::now();
                let mut seen = 0usize;
                for (epk, esig) in edv.iter() {
                    if seen >= t { break; }
                    epk.verify(&cm, esig).unwrap(); seen += 1;
                }
                for (epk, esig, qb, qo, qm2) in hyb.iter() {
                    if seen >= t { break; }
                    verify_hyb!($mod, epk, esig, qb, qo, &cm, qm2); seen += 1;
                }
                xs.push(t0.elapsed().as_nanos());
            }
            let ss = stat(&mut xs);
            // m=n full signing exposes n_ed = n-k classical keys; short-circuit
            // consumes min(t, n_ed) classical then fills the rest with hybrid
            let n_c_first = t.min(edv.len());
            let n_q_first = t - n_c_first;
            let pred_sc = n_c_first as f64 * $ed.med + n_q_first as f64 * ($ed.med + $pq.med);
            $w.push_str(&format!("{},{},{},{},verifyall,{:.3},{:.3},{:.3},,\n",
                $label, t, k, n, sa.p25, sa.med, sa.p75));
            $w.push_str(&format!("{},{},{},{},shortcircuit,{:.3},{:.3},{:.3},{:.3},{:.3}\n",
                $label, t, k, n, ss.p25, ss.med, ss.p75, pred_sc, ss.med - pred_sc));
        }
    }};
}

fn falcon_length_distribution(w: &mut String, probes: usize) {
    use pqcrypto_falcon::falcon512 as m;
    use pqcrypto_traits::sign::DetachedSignature as DS;
    let mut lens = Vec::with_capacity(probes);
    for i in 0..probes {
        let (_pk, sk) = m::keypair();
        let d = m::detached_sign(format!("len-probe-{i}").as_bytes(), &sk);
        lens.push(d.as_bytes().len());
    }
    lens.sort_unstable();
    let mean = lens.iter().sum::<usize>() as f64 / lens.len() as f64;
    w.push_str(&format!("# fndsa512 sig length n={}: min={} med={} max={} mean={:.2}\n",
        probes, lens[0], lens[lens.len()/2], lens[lens.len()-1], mean));
}

fn main() {
    let out = env::args().nth(1).unwrap_or_else(|| {
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../results/e4_latency").to_string()
    });
    let iters: usize = env::args().nth(2).map(|x| x.parse().unwrap()).unwrap_or(1000);
    fs::create_dir_all(&out).unwrap();

    // ML-DSA-65 grid
    {
        let ed = ed_verify_stat(iters);
        let pq = pq_verify_stat!(pqcrypto_dilithium::dilithium3, iters);
        let mut w = format!(
            "# primitive verify med(us): ed25519={:.3} mldsa65={:.3} hybrid={:.3}\n\
             variant,t,k,m,mode,p25_us,med_us,p75_us,pred_med_us,resid_us\n",
            ed.med, pq.med, ed.med + pq.med);
        role_grid!(pqcrypto_dilithium::dilithium3, "mldsa65",
                   b"PQTUF-v1|hyb:ed25519:mldsa65|Q|", w, iters, ed, pq);
        let path = std::path::Path::new(&out).join("rolebench_mldsa65.csv");
        std::fs::write(&path, w.as_bytes()).unwrap();
        println!("wrote {}", path.display());
    }
    // FN-DSA-512 grid + variable length distribution
    {
        let ed = ed_verify_stat(iters);
        let pq = pq_verify_stat!(pqcrypto_falcon::falcon512, iters);
        let mut w = format!(
            "# primitive verify med(us): ed25519={:.3} fndsa512={:.3} hybrid={:.3}\n\
             variant,t,k,m,mode,p25_us,med_us,p75_us,pred_med_us,resid_us\n",
            ed.med, pq.med, ed.med + pq.med);
        role_grid!(pqcrypto_falcon::falcon512, "fndsa512",
                   b"PQTUF-v1|hyb:ed25519:fndsa512|Q|", w, iters, ed, pq);
        falcon_length_distribution(&mut w, 3000);
        let path = std::path::Path::new(&out).join("rolebench_fndsa512.csv");
        std::fs::write(&path, w.as_bytes()).unwrap();
        println!("wrote {}", path.display());
    }
}
