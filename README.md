# php2shell Lab

Reproduction environment for CVE-2026-109618 and CVE-2026-109619.

## Quick start

```bash
docker build -t php2shell-lab .
docker run -d --name php2shell-lab -p 8080:80 php2shell-lab

# Verify the environment
curl http://localhost:8080/

# Run tests
chmod +x test_oom.sh test_stale.sh
./test_oom.sh
./test_stale.sh

# Watch for crashes / errors
docker logs -f php2shell-lab
```

For deterministic CVE-2026-109619 testing (single worker):

```bash
docker run -d --name php2shell-lab -p 8080:80 \
    -v $(pwd)/apache-single-worker.conf:/etc/apache2/conf-enabled/single-worker.conf \
    php2shell-lab
```


## What each CVE is

### CVE-2026-109618: OOM corruption (GHSA-w8hw-w9fx-j79w)

**Root cause:** PHP uses `longjmp()` ("bailout") to abort when memory runs out.
If the OOM happens during request initialization (RINIT), internal data
structures are left half-built. The request shutdown code (RSHUTDOWN) then
walks those structures assuming they're valid. This is CWE-416 (Use After
Free) because the cleanup code dereferences pointers into memory that was
never properly initialized or has been freed.

**Attack surface:** Any request that causes PHP to allocate past `memory_limit`
during the C-level request parsing phase. Confirmed on Apache + mod_php with
both multipart uploads and normal form POST data.

**Key insight:** The vulnerability is NOT in userland PHP code. It's in the
C-level request lifecycle. Your PHP script doesn't even need to run for this
to fire. The OOM happens during parsing of the incoming HTTP request, before
`<?php` executes.


### CVE-2026-109619: Stale global state (GHSA-6wmf-4rv5-p3rp)

**Root cause:** PHP's internal globals (the Executor Globals / `EG()` macro in
the source) hold request-specific state. When a request ends, this memory is
freed, but under this bug, some pointers in the globals are not cleared.
When the same worker handles the next request, it can access these dangling
pointers before the normal RINIT initialization overwrites them.

**Attack surface:** Two confirmed trigger paths:

1. `session.upload_progress`: PHP creates internal tracking state during file
   uploads when this is enabled. The tracking state becomes stale after the
   request.

2. Fatal error + per-request ini settings: A fatal error during request
   processing (or a timeout) leaves globals in a dirty state. If the request
   also had per-request ini values that emit warnings/diagnostics, the error
   handler touches the stale globals.

**Key insight:** This is a two-request attack. Request 1 poisons the worker's
global state. Request 2 (on the same worker) dereferences the dangling
pointers. With Apache prefork MPM, workers handle requests serially, so
landing on the same worker is deterministic if you control the pool size.


## How the lab maps to each CVE

```
File                     CVE it targets       What it does
---------------------------------------------------------------------
php-vuln.ini             Both                 memory_limit=32M (109618),
                                              upload_progress=1 (109619)
app/oom_target.php       CVE-2026-109618      POST endpoint for OOM tests
app/stale_target.php     CVE-2026-109619      Session + fatal error paths
apache-single-worker.conf CVE-2026-109619     Forces single worker for
                                              deterministic same-PID hits
test_oom.sh              CVE-2026-109618      Sends crafted POST payloads
test_stale.sh            CVE-2026-109619      Two-request sequences
```


## Studying the patch

The fix is a single commit across all branches. Start here:

```bash
git clone https://github.com/php/php-src.git
cd php-src
git show 31c0ea7d7f
```

What the commit does:

1. **Replaces bailout on OOM with UnwindExit.** Instead of `longjmp()` which
   skips over all cleanup, PHP now uses a controlled unwind that lets each
   stack frame clean up properly. This is the core fix for CVE-2026-109618.

2. **Resets globals between requests.** The commit adds explicit zeroing of
   `EG(user_error_handler)`, `EG(user_exception_handler)`, and the error
   handler stacks during shutdown. This closes the stale pointer paths for
   CVE-2026-109619.

What to look for in the diff:

- `Zend/zend_execute_API.c`: the globals that get reset in
  `zend_shutdown_executor_values()`
- The test files `oom_request_parsing_next_request.phpt` and
  `oom_shutdown_function_next_request.phpt` show PHP's own reproduction
  cases. These are your best reference for what sequences the PHP team
  validated.
- Search for `ZVAL_UNDEF` and `memset` calls added in the shutdown path.
  Each one closes a specific dangling pointer.


## Going deeper: building PHP with AddressSanitizer

If you want to see the actual UAF in action rather than just the crash,
build PHP from source with ASAN:

```bash
git clone https://github.com/php/php-src.git
cd php-src
git checkout PHP-8.4.26  # pre-patch version

./buildconf
./configure \
    --with-apxs2=/usr/bin/apxs2 \
    --enable-address-sanitizer \
    --enable-debug \
    --disable-zts

make -j$(nproc)
```

ASAN will print the exact allocation/free/use-after-free stack traces
instead of just segfaulting, showing you precisely which data structure
was corrupted and where in the request lifecycle it happened.

This is more involved than the Docker setup, but it gives you the actual
proof of the memory corruption rather than just inferring it from crashes.


## What this lab does NOT give you

A working RCE exploit. The gap between triggering the memory corruption
and achieving code execution is significant. You would need to:

1. Control what gets allocated in the freed region (heap shaping)
2. Find a useful primitive in PHP's object layout (type confusion target)
3. Chain that into arbitrary read/write
4. Pivot to code execution

That's exploit development, not vulnerability reproduction. The lab gets
you to step 0: reliably triggering the corruption under controlled
conditions with observable output (crashes, ASAN reports).

watchTowr has done the full chain for 109618 and is withholding it. When
(not if) a full PoC drops publicly, you can run it against this lab
environment directly.
