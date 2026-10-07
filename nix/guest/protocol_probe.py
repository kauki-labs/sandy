#!/usr/bin/env python3
"""Ground-truth probe for the sandy console protocol (#26).

Mirrors sandy's `run_console`: spawn the microvm runner, scan serial stdout for
the READY_MARKER (`sandy login:`), inject the exact base64-wrapped command frame
sandy builds, capture bytes between the per-run START/END sentinels, parse the
trailing `exit=<n>`. Proves the GUEST speaks the protocol before sandy's backend
drives it. Not shipped — a spike artifact.
"""

import base64
import os
import pty
import re
import select
import subprocess
import sys
import time
import uuid

RUNNER = sys.argv[1]  # path to the microvm-run binary
COMMAND = sys.argv[2] if len(sys.argv) > 2 else "echo hi"

READY = b"sandy login:"
run_id = uuid.uuid4()
START = f"<<SANDY-{run_id}-START>>".encode()
END = f"<<SANDY-{run_id}-END>>".encode()
encoded = base64.b64encode(COMMAND.encode()).decode()


def split_emit(marker: bytes) -> str:
    """printf the marker from two split literals so the ECHOED input never
    contains the contiguous marker — only the printf OUTPUT assembles it."""
    s = marker.decode()
    mid = len(s) // 2
    return f"printf '%s%s' '{s[:mid]}' '{s[mid:]}'"


# sandy's frame: START, command output, END immediately followed by `exit=N`
# on the SAME line (the parser reads exit= from the first line after END, so no
# blank line between). Sentinels are split so the guest tty echo can't carry a
# contiguous copy.
FRAME = (
    f"{split_emit(START)}; printf '%s' '{encoded}' | base64 -d | sh; __rc=$?; "
    f"{split_emit(END)}; printf 'exit=%d\\n' \"$__rc\"\n"
).encode()

# Serial is on stdio; give qemu a real tty so getty behaves as on a console.
primary, secondary = pty.openpty()
proc = subprocess.Popen(
    [RUNNER], stdin=secondary, stdout=secondary, stderr=subprocess.STDOUT, close_fds=True
)
os.close(secondary)

buf = bytearray()
deadline = time.time() + 90
injected = False
captured = None
exit_code = None


def drain():
    r, _, _ = select.select([primary], [], [], 0.5)
    if primary in r:
        try:
            chunk = os.read(primary, 4096)
        except OSError:
            return b""
        buf.extend(chunk)
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
        return chunk
    return b""


while time.time() < deadline:
    drain()
    if not injected and READY in buf:
        time.sleep(0.5)  # let autologin hand off to the shell
        os.write(primary, FRAME)
        injected = True
        buf.clear()
        continue
    if injected and END in buf:
        # sandy-faithful parse: capture between the first contiguous START/END,
        # and read exit= from the FIRST line after END (not a loose regex over
        # the rest). Proves the frame is compatible with the real state machine.
        start_i = buf.find(START)
        end_i = buf.find(END)
        if start_i != -1 and end_i != -1:
            captured = bytes(buf[start_i + len(START) : end_i])
        after = bytes(buf[end_i + len(END) :])
        nl = after.find(b"\n")
        first_line = after if nl == -1 else after[: nl + 1]
        m = re.search(rb"exit=(-?\d+)", first_line)
        if m:
            exit_code = int(m.group(1))
            break

proc.terminate()
try:
    proc.wait(timeout=5)
except subprocess.TimeoutExpired:
    proc.kill()

print("\n\n==== PROBE RESULT ====", flush=True)
print(f"booted(ready seen): {injected}")
print(f"captured: {captured!r}")
print(f"exit_code: {exit_code}")
ok = injected and exit_code == 0 and captured is not None and b"hi" in captured
print(f"PROTOCOL_OK: {ok}")
sys.exit(0 if ok else 1)
