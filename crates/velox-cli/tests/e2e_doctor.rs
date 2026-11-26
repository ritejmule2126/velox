//! The real `velox doctor` binary: exit codes and output formats.
#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

fn doctor(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_velox")).arg("doctor").args(args).output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A small, valid configuration whose limits any CI machine satisfies.
fn write_config(dir: &std::path::Path, extra: &str) -> String {
    let path = dir.join("velox.toml");
    std::fs::write(
        &path,
        format!(
            "[server]\nhttp_addr = \"127.0.0.1:0\"\n[limits]\nmax_connections = 8\n{extra}\n\
             [[upstream]]\nname = \"a\"\nbackends = [{{ addr = \"127.0.0.1:1\" }}]\n[[route]]\nupstream = \"a\"\n"
        ),
    )
    .unwrap();
    path.display().to_string()
}

#[test]
fn a_healthy_setup_exits_zero_and_explains_itself() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), "");
    let (ok, stdout, stderr) = doctor(&["-c", &cfg]);
    assert!(ok, "{stdout}\n{stderr}");
    assert!(stdout.contains("[ OK ] config") && stdout.contains("parses and validates"), "{stdout}");
    assert!(
        stdout.contains("fd-limit") && stdout.contains("accept-workers") && stdout.contains("allocator"),
        "{stdout}"
    );
    assert!(stdout.contains("0 failure(s)"), "{stdout}");
    // The allocator line tells the truth about this build.
    if cfg!(feature = "mimalloc") {
        assert!(stdout.contains("mimalloc (compiled in)"), "{stdout}");
    }
}

#[test]
fn a_broken_configuration_exits_non_zero_with_the_reason() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.toml");
    std::fs::write(&bad, "[server]\nhttp_addr = \"127.0.0.1:1\"\n[[route]]\nupstream = \"ghost\"\n").unwrap();
    let (ok, stdout, stderr) = doctor(&["-c", &bad.display().to_string()]);
    assert!(!ok);
    assert!(stdout.contains("[FAIL] config") && stdout.contains("unknown upstream"), "{stdout}");
    assert!(stderr.contains("doctor found 1 failure(s)"), "{stderr}");
    let (ok, _, stderr) = doctor(&["-c", &dir.path().join("missing.toml").display().to_string()]);
    assert!(!ok && stderr.contains("failure"), "{stderr}");
}

#[test]
fn warnings_only_fail_the_run_under_strict() {
    let dir = tempfile::tempdir().unwrap();
    // accept_workers far above any CPU count is always a warning.
    let cfg = write_config(dir.path(), "");
    let text = std::fs::read_to_string(&cfg).unwrap().replace("[limits]", "accept_workers = 200\n[limits]");
    std::fs::write(&cfg, text).unwrap();
    let (ok, stdout, _) = doctor(&["-c", &cfg]);
    assert!(ok, "warnings alone must not fail: {stdout}");
    assert!(stdout.contains("[WARN] accept-workers"), "{stdout}");
    let (ok, _, stderr) = doctor(&["-c", &cfg, "--strict"]);
    assert!(!ok && stderr.contains("--strict"), "{stderr}");
}

#[test]
fn json_output_is_machine_readable() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), "");
    let (ok, stdout, _) = doctor(&["-c", &cfg, "--json"]);
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}: {stdout}"));
    let checks = v["checks"].as_array().unwrap();
    assert_eq!(checks[0]["name"], "config");
    assert_eq!(checks[0]["status"], "ok");
    assert!(checks.iter().all(|c| ["ok", "warn", "fail", "skip"].contains(&c["status"].as_str().unwrap())));
}

#[test]
fn an_expiring_certificate_and_a_taken_port_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    let mut p = rcgen::CertificateParams::new(vec!["a.test".into()]).unwrap();
    let now = time::OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::days(60);
    p.not_after = now + time::Duration::days(3);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = p.self_signed(&key).unwrap();
    let (c, k) = (dir.path().join("c.pem"), dir.path().join("k.pem"));
    std::fs::write(&c, cert.pem()).unwrap();
    std::fs::write(&k, key.serialize_pem()).unwrap();
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); // a port that is genuinely busy
    let port = held.local_addr().unwrap().port();
    let cfg = dir.path().join("velox.toml");
    std::fs::write(
        &cfg,
        format!(
            "[server]\nhttp_addr = \"127.0.0.1:{port}\"\nhttps_addr = \"127.0.0.1:0\"\nh3 = false\n[limits]\nmax_connections = 8\n\
             [[tls.certs]]\ncert_file = \"{}\"\nkey_file = \"{}\"\n\
             [[upstream]]\nname = \"a\"\nbackends = [{{ addr = \"127.0.0.1:1\" }}]\n[[route]]\nupstream = \"a\"\n",
            c.display(),
            k.display()
        ),
    )
    .unwrap();
    let (ok, stdout, _) = doctor(&["-c", &cfg.display().to_string()]);
    assert!(ok, "{stdout}");
    assert!(
        stdout.contains("[WARN] tls-expiry") && stdout.contains("day(s) left") && stdout.contains("velox reload"),
        "{stdout}"
    );
    assert!(stdout.contains("[WARN] listeners") && stdout.contains("already in use"), "{stdout}");
    drop(held);
}
