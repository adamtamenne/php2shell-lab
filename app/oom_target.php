<?php
// CVE-2026-109618: OOM corruption target
//
// WHAT THIS CVE IS ABOUT:
// When PHP hits memory_limit, it calls longjmp() to bail out of the
// current execution context. If this happens while internal request
// data structures are being initialized (during RINIT / request
// parsing), those structures are left half-built. The shutdown/cleanup
// code (RSHUTDOWN) then walks those structures assuming they're valid,
// leading to use-after-free / type confusion.
//
// WHY THIS FILE EXISTS:
// This gives you a target endpoint that processes POST data. The real
// attack is about what happens INSIDE PHP's request parsing layer
// (before your userland code even runs), not in this script itself.
// The script just needs to exist so Apache routes requests to mod_php.
//
// WHAT TO TRY:
// 1. Send multipart POST requests with payloads designed to push PHP
//    past 32M during the C-level request parsing phase.
// 2. Send many form fields (not file uploads) - the advisory confirms
//    "normal form posts can also trigger CVE-2026-109618 on mod_php."
// 3. Watch `docker logs` for the Fatal error about memory exhaustion.
// 4. The interesting question: what state is corrupted when the
//    bailout fires during RINIT vs. during userland execution?
//    Study the commit diff to see which structures get reset.

// Simple form processing - keeps the endpoint functional
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Log what PHP sees after request parsing completes
    error_log("[oom_target] POST received - field count: " . count($_POST));
    error_log("[oom_target] FILES count: " . count($_FILES));
    error_log("[oom_target] memory_usage: " . memory_get_usage(true));

    echo "POST processed.\n";
    echo "Fields: " . count($_POST) . "\n";
    echo "Files: " . count($_FILES) . "\n";
    echo "Memory: " . memory_get_usage(true) . "\n";
} else {
    echo "Send POST data to this endpoint.\n";
    echo "memory_limit: " . ini_get('memory_limit') . "\n";
}
