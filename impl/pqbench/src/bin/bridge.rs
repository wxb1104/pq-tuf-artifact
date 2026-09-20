// pqbridge: long-lived PQClean signing bridge for the PQ-TUF Python prototype.
//
// Line protocol (one request / response per line, hex payloads -> no new deps):
//   keygen <alg>                       -> OK pk=<hex> sk=<hex>
//   sign <alg> <sk_hex> <msg_hex>      -> OK sig=<hex>
//   verify <alg> <pk_hex> <msg_hex> <sig_hex> -> OK valid=1 | OK valid=0
//   sizes <alg>                        -> OK pk=<bytes> sig=<bytes>
//   ping -> OK pong ; quit -> exit
//
// algs: mldsa44 mldsa65 mldsa87 fndsa512 fndsa1024
//       slhdsa128s slhdsa128f slhdsa256s slhdsa256f
// Backend: PQClean via pqcrypto-rs (same source/versions as pqbench, so all
// sizes/timings are consistent with the E1 primitive benchmark).
use std::io::{self, BufRead, Write};

use pqcrypto_traits::sign::{
    DetachedSignature as DSig, PublicKey as PKt, SecretKey as SKt,
};

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}
fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    let h = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err("bad hex digit".into()),
        }
    };
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        out.push((h(b[i])? << 4) | h(b[i + 1])?);
        i += 2;
    }
    Ok(out)
}

macro_rules! algs {
    ($($name:literal => $m:path),* $(,)?) => {
        fn keygen(alg: &str) -> Option<(String, String)> {
            match alg {
                $($name => {
                    use $m::{keypair};
                    let (pk, sk) = keypair();
                    Some((hex(pk.as_bytes()), hex(sk.as_bytes())))
                })*
                _ => None,
            }
        }
        fn sign(alg: &str, skh: &str, msg: &[u8]) -> Result<Option<String>, String> {
            match alg {
                $($name => {
                    use $m::{detached_sign, SecretKey, DetachedSignature};
                    let skb = unhex(skh)?;
                    let sk = SecretKey::from_bytes(&skb).map_err(|e| format!("sk: {e}"))?;
                    let sig = detached_sign(msg, &sk);
                    Ok(Some(hex(DetachedSignature::as_bytes(&sig))))
                })*
                _ => Ok(None),
            }
        }
        fn verify(alg: &str, pkh: &str, msg: &[u8], sigh: &str) -> Result<Option<bool>, String> {
            match alg {
                $($name => {
                    use $m::{verify_detached_signature, PublicKey, DetachedSignature};
                    let pkb = unhex(pkh)?;
                    let sigb = unhex(sigh)?;
                    let pk = PublicKey::from_bytes(&pkb).map_err(|e| format!("pk: {e}"))?;
                    let sig = DetachedSignature::from_bytes(&sigb).map_err(|e| format!("sig: {e}"))?;
                    Ok(Some(verify_detached_signature(&sig, msg, &pk).is_ok()))
                })*
                _ => Ok(None),
            }
        }
        fn sizes(alg: &str) -> Option<(usize, usize)> {
            match alg {
                $($name => {
                    use $m::{keypair, detached_sign};
                    let (pk, sk) = keypair();
                    let sig = detached_sign(b"size-probe", &sk);
                    drop(sk);
                    Some((pk.as_bytes().len(), sig.as_bytes().len()))
                })*
                _ => None,
            }
        }
    };
}

algs! {
    "mldsa44"    => pqcrypto_dilithium::dilithium2,
    "mldsa65"    => pqcrypto_dilithium::dilithium3,
    "mldsa87"    => pqcrypto_dilithium::dilithium5,
    "fndsa512"   => pqcrypto_falcon::falcon512,
    "fndsa1024"  => pqcrypto_falcon::falcon1024,
    "slhdsa128s" => pqcrypto_sphincsplus::sphincssha2128ssimple,
    "slhdsa128f" => pqcrypto_sphincsplus::sphincssha2128fsimple,
    "slhdsa256s" => pqcrypto_sphincsplus::sphincssha2256ssimple,
    "slhdsa256f" => pqcrypto_sphincsplus::sphincssha2256fsimple,
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut line = String::new();
    loop {
        line.clear();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let parts: Vec<&str> = t.split(' ').collect();
        let resp: String = match parts[0] {
            "ping" => "OK pong".into(),
            "quit" | "exit" => {
                let _ = writeln!(stdout, "OK bye");
                let _ = stdout.flush();
                break;
            }
            "keygen" if parts.len() == 2 => match keygen(parts[1]) {
                Some((pk, sk)) => format!("OK pk={pk} sk={sk}"),
                None => format!("ERR unknown alg {}", parts[1]),
            },
            "sign" if parts.len() == 4 => match (|| -> Result<String, String> {
                let msg = unhex(parts[3])?;
                match sign(parts[1], parts[2], &msg)? {
                    Some(s) => Ok(format!("OK sig={s}")),
                    None => Ok(format!("ERR unknown alg {}", parts[1])),
                }
            })() {
                Ok(r) => r,
                Err(e) => format!("ERR {e}"),
            },
            "verify" if parts.len() == 5 => match (|| -> Result<String, String> {
                let msg = unhex(parts[3])?;
                match verify(parts[1], parts[2], &msg, parts[4])? {
                    Some(b) => Ok(format!("OK valid={}", b as u8)),
                    None => Ok(format!("ERR unknown alg {}", parts[1])),
                }
            })() {
                Ok(r) => r,
                Err(e) => format!("ERR {e}"),
            },
            "sizes" if parts.len() == 2 => match sizes(parts[1]) {
                Some((p, s)) => format!("OK pk={p} sig={s}"),
                None => format!("ERR unknown alg {}", parts[1]),
            },
            _ => "ERR bad request".into(),
        };
        let _ = writeln!(stdout, "{resp}");
        let _ = stdout.flush();
    }
}
