// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// NOTE: This test sends a shutdown signal to itself,
// so it needs to be in an isolated test to prevent concurrency.

use pingora_core::server::{configuration::ServerConf, ExecutionPhase, RunArgs, Server};

/// Verify that a signal received **during** the grace period causes the server to exit
/// early instead of waiting for the full grace period to elapse.
///
/// Before this fix, `run()` used a bare `thread::sleep(grace_period)` after consuming
/// the signal handlers in `main_loop`, so no signal could interrupt it.
#[test]
fn test_signal_during_grace_period_exits_early() {
    let conf = ServerConf {
        // Long grace period — the fix must cause early exit well before this.
        grace_period_seconds: Some(30),
        graceful_shutdown_timeout_seconds: Some(1),
        ..Default::default()
    };
    let mut server = Server::new_with_opt_and_conf(None, conf);

    let mut phase = server.watch_execution_phase();

    let join = std::thread::spawn(move || {
        server.bootstrap();
        server.run(RunArgs::default());
    });

    assert!(matches!(
        phase.blocking_recv().unwrap(),
        ExecutionPhase::Bootstrap
    ));
    assert!(matches!(
        phase.blocking_recv().unwrap(),
        ExecutionPhase::BootstrapComplete,
    ));
    assert!(matches!(
        phase.blocking_recv().unwrap(),
        ExecutionPhase::Running,
    ));

    // Wait for the main_loop signal handlers to be installed.
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Trigger a graceful shutdown with a 30-second grace period.
    unsafe {
        libc::raise(libc::SIGTERM);
    }

    assert!(matches!(
        phase.blocking_recv().unwrap(),
        ExecutionPhase::GracefulTerminate,
    ));
    assert!(matches!(
        phase.blocking_recv().unwrap(),
        ExecutionPhase::ShutdownStarted,
    ));
    assert!(matches!(
        phase.blocking_recv().unwrap(),
        ExecutionPhase::ShutdownGracePeriod,
    ));

    // The grace-period polling loop checks fast_exit once per second. Wait long enough
    // for the signal-watcher thread to have registered its handlers (first iteration of
    // the polling loop takes 1 s) before sending the interrupting signal.
    std::thread::sleep(std::time::Duration::from_millis(1500));

    let interrupt_at = std::time::Instant::now();
    unsafe {
        libc::raise(libc::SIGTERM);
    }

    assert!(matches!(
        phase.blocking_recv().unwrap(),
        ExecutionPhase::ShutdownRuntimes,
    ));
    let elapsed = interrupt_at.elapsed();

    // Must exit well before the remaining 28+ seconds of the grace period.
    assert!(
        elapsed.as_secs() < 5,
        "expected early exit in <5s after second SIGTERM, took {elapsed:?}"
    );

    join.join().unwrap();

    assert!(matches!(
        phase.blocking_recv().unwrap(),
        ExecutionPhase::Terminated,
    ));
}
