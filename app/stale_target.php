<?php
// CVE-2026-109619: Stale global state / use-after-free target
//
// WHAT THIS CVE IS ABOUT:
// Request-specific internal state (in PHP's C globals) can survive
// after its backing memory is freed. When the same Apache worker
// handles the NEXT request, it may access that stale state before
// the normal RINIT initialization resets it. Classic UAF.
//
// THE TWO CONFIRMED TRIGGER PATHS:
//
// Path 1: session.upload_progress
//   PHP tracks upload progress in session data. The tracking creates
//   internal state tied to the request. If that state's memory is freed
//   but the pointer persists in the worker's globals, the next request
//   on the same worker dereferences a dangling pointer.
//
// Path 2: Fatal error + per-request ini settings
//   The advisory says "a warning from [a per-request PHP setting] is
//   one of the two confirmed triggers." If a request triggers a fatal
//   error (or timeout), and PHP has set per-request ini values that
//   emit diagnostics, the error handler may access globals that
//   weren't properly cleaned up.
//
// WHY THIS IS A TWO-REQUEST ATTACK:
//   Request 1 (to this worker): creates the stale state, then the
//     request ends and memory is freed but pointers aren't cleared.
//   Request 2 (to the SAME worker): accesses the dangling pointer
//     before RINIT has a chance to reset it.
//
// The challenge: you need both requests to land on the same Apache
// worker process. With mod_php prefork MPM, each worker handles one
// request at a time sequentially, which makes this deterministic if
// you can identify and target a specific worker.

session_start();

$action = $_GET['action'] ?? 'info';

switch ($action) {
    case 'info':
        // Show worker PID - you need this to confirm both requests
        // hit the same worker process.
        echo "Worker PID: " . getmypid() . "\n";
        echo "Session ID: " . session_id() . "\n";
        echo "upload_progress.enabled: " . ini_get('session.upload_progress.enabled') . "\n";
        break;

    case 'fatal':
        // Attacker-reachable fatal error path.
        // The advisory says the FPM exploitation path "depends on a
        // suitable application operation." This simulates an endpoint
        // where an attacker can trigger a fatal error.
        //
        // In real applications this could be: calling a method on null,
        // type errors from attacker-controlled input, exhausting a
        // resource, or hitting a timeout.
        error_log("[stale_target] About to trigger fatal error on PID " . getmypid());

        // Trigger a real fatal error (not catchable)
        // This forces PHP into the error/shutdown path where stale
        // globals become dangerous.
        $x = new class {
            public function __toString(): string {
                // This will cause a fatal error in the engine
                throw new \Error("Fatal from __toString");
            }
        };
        // Triggering the fatal: using the object in a string context
        // where the engine doesn't expect an exception
        echo $x;
        break;

    case 'upload_form':
        // Form that uses session.upload_progress - this is the
        // confirmed trigger mechanism for CVE-2026-109619.
        // The hidden field PHP_SESSION_UPLOAD_PROGRESS tells PHP to
        // track the upload in the session, creating the internal state
        // that can become stale.
        ?>
        <form action="stale_target.php?action=upload" method="POST" enctype="multipart/form-data">
            <input type="hidden" name="<?= ini_get('session.upload_progress.name') ?>" value="lab_test">
            <input type="file" name="testfile">
            <button type="submit">Upload (triggers session upload progress tracking)</button>
        </form>
        <?php
        break;

    case 'upload':
        echo "Upload processed on PID: " . getmypid() . "\n";
        echo "Session upload progress key: " . ini_get('session.upload_progress.prefix') . "lab_test\n";
        if (isset($_SESSION)) {
            echo "Session contents:\n";
            print_r($_SESSION);
        }
        break;

    default:
        echo "Unknown action. Use: info, fatal, upload_form, upload\n";
}
