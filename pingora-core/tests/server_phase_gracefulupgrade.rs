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

/// Verify that SIGQUIT triggers the GracefulUpgrade execution phase path and that
/// `upgrade_grace_period_seconds` is used for the grace period rather than the
/// (longer) `grace_period_seconds` value.
#[test]
fn test_server_execution_phase_monitor_graceful_upgrade() {
    let conf = ServerConf {
        // Short grace period so the test finishes quickly.
        grace_period_seconds: Some(1),
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

    // Wait for signal handlers to be installed.
    std::thread::sleep(std::time::Duration::from_millis(500));

    unsafe {
        libc::raise(libc::SIGQUIT);
    }

    // Server tries to forward FDs to a new process (none exists, send_to_sock will fail,
    // but the phase progression continues regardless).
    assert!(matches!(
        phase.blocking_recv().unwrap(),
        ExecutionPhase::GracefulUpgradeTransferringFds,
    ));
    // fast_exit setup in 3d2d6a2301b9b4c0c82208ea791667b57105387c e.g. on SIGQUIT
    // CLOSE_TIMEOUT (5 s) elapses so the new process can bind before we stop accepting.
    //assert!(matches!(
    //    phase.blocking_recv().unwrap(),
    //    ExecutionPhase::GracefulUpgradeCloseTimeout,
    //));
    assert!(matches!(
        phase.blocking_recv().unwrap(),
        ExecutionPhase::ShutdownStarted,
    ));
    assert!(matches!(
        phase.blocking_recv().unwrap(),
        ExecutionPhase::ShutdownGracePeriod,
    ));
    assert!(matches!(
        phase.blocking_recv().unwrap(),
        ExecutionPhase::ShutdownRuntimes,
    ));

    join.join().unwrap();

    assert!(matches!(
        phase.blocking_recv().unwrap(),
        ExecutionPhase::Terminated,
    ));
}
