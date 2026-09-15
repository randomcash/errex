//! CLI coverage for `errexd healthcheck` — the container HEALTHCHECK path.
//!
//! Configuration goes through `ERREX_*` env vars rather than flags because
//! the flattened `Config` args belong to the top-level command (they would
//! have to precede the subcommand name), and env vars are how a container
//! configures the daemon anyway.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};

/// A daemon invocation with every inherited `ERREX_*` var cleared — the
/// developer shell running the suite must not change what these assert.
fn errexd(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_errexd"));
    for var in ["ERREX_HOST", "ERREX_PORT", "ERREX_MCP_HOST", "PORT"] {
        cmd.env_remove(var);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.args(args).output().expect("spawn errexd")
}

/// The bug behind issue #14: a container bound to loopback publishes a dead
/// port while the healthcheck — probing loopback from inside — stays green.
/// Under `--require-public-bind` that configuration must report unhealthy.
#[test]
fn require_public_bind_rejects_a_loopback_bind() {
    let out = errexd(
        &["healthcheck", "--require-public-bind"],
        &[("ERREX_HOST", "127.0.0.1")],
    );
    assert!(
        !out.status.success(),
        "loopback bind must be reported unhealthy, got {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ERREX_HOST"),
        "the error must name the variable to fix, got: {stderr}"
    );
}

/// The gate must not fire on a public bind: with `0.0.0.0` the probe gets
/// as far as dialing, and fails only because nothing is listening.
#[test]
fn require_public_bind_allows_a_public_bind() {
    let out = errexd(
        &["healthcheck", "--require-public-bind"],
        &[("ERREX_HOST", "0.0.0.0"), ("ERREX_PORT", "1")],
    );
    assert!(!out.status.success(), "nothing is listening on port 1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("connect to daemon"),
        "should fail at connect, not at the bind gate, got: {stderr}"
    );
}

/// The probe target used to be hard-coded at `127.0.0.1:9090`, so moving the
/// port left the container permanently unhealthy while it served fine. Serve
/// a 200 on an ephemeral port and require the probe to find it.
#[test]
fn healthcheck_follows_the_configured_port() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind probe target");
    let port = listener.local_addr().unwrap().port();

    // Non-blocking accept with a deadline: a blocking accept would hang the
    // suite for its full timeout whenever the probe dials the wrong port,
    // which is precisely the regression this test exists to catch.
    listener
        .set_nonblocking(true)
        .expect("non-blocking listener");
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).expect("blocking stream");
                    let mut buf = [0u8; 256];
                    let _ = stream.read(&mut buf);
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .expect("write health response");
                    // Dropping the stream closes the connection, which is
                    // what lets the probe's read_to_end return.
                    return true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("accept failed: {e}"),
            }
        }
        false
    });

    let out = errexd(
        &["healthcheck"],
        &[
            ("ERREX_HOST", "127.0.0.1"),
            ("ERREX_PORT", &port.to_string()),
        ],
    );
    let probed = server.join().expect("probe server thread");

    assert!(
        out.status.success(),
        "probe should have found the listener on :{port}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        probed,
        "probe never connected to the configured port :{port}"
    );
}
