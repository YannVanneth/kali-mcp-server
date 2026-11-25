import codecs
import contextvars
import os
import re
import selectors
import shlex
import signal
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

DEFAULT_TIMEOUT = 120  # seconds


def env_int(name: str, default: int, minimum: int = 0) -> int:
    """Read an integer setting, falling back to the default when invalid."""
    try:
        return max(minimum, int(os.environ.get(name, "") or default))
    except ValueError:
        return default


# Resource limits. 0 disables a limit (except the concurrency limit).
MAX_CONCURRENT = env_int("KALI_MCP_MAX_CONCURRENT", 2, minimum=1)
TOOL_MEMORY_MB = env_int("KALI_MCP_TOOL_MEMORY_MB", 2048)
MAX_OUTPUT_BYTES = env_int("KALI_MCP_MAX_OUTPUT_BYTES", 8 * 1024 * 1024)
MAX_SPOOL_BYTES = env_int("KALI_MCP_MAX_SPOOL_BYTES", 256 * 1024 * 1024)
QUEUE_TIMEOUT = 300  # seconds a call may wait for a free slot
KEPT_OUTPUT_FILES = 8  # newest truncated outputs retained on disk
_OUTPUT_PREFIX = "kali-mcp-output-"
# /tmp is frequently a RAM-backed tmpfs, which would defeat spooling to disk.
SPOOL_DIR = os.environ.get("KALI_MCP_SPOOL_DIR", "") or (
    "/var/tmp" if os.access("/var/tmp", os.W_OK) else tempfile.gettempdir()
)

_slots = threading.BoundedSemaphore(MAX_CONCURRENT)
# Set by the server when the client cancels a call or disconnects.
cancel_event: contextvars.ContextVar[threading.Event | None] = contextvars.ContextVar(
    "kali_mcp_cancel_event", default=None
)
BLOCKED_COMMANDS = {
    "rm", "mv", "cp", "dd", "mkfs", "shutdown", "reboot", "poweroff",
    "init", "systemctl", "chown", "chmod", "wget", "curl",
}

# Splits a command string into candidate tokens on whitespace and every
# shell metacharacter, so tokens hidden behind chaining or substitution
# (e.g. "echo hi; rm -rf /", "$(rm -rf /)", `rm -rf /`, "cat x | rm")
# are still checked against the denylist.
_SHELL_TOKEN_SPLIT = re.compile(r"[\s;|&><`$()]+")

# Commands that could damage the Kali system itself. Full shell syntax
# (pipes, chaining, redirection, substitution) is allowed; only these
# destructive binaries are refused.
DANGEROUS_PATTERNS = [
    r"\brm\b", r"\bmv\b", r"\bcp\b", r"\bdd\b", r"\bmkfs\b",
    r"\bshutdown\b", r"\breboot\b", r"\bpoweroff\b", r"\binit\b",
    r"\bsystemctl\b", r"\bchown\b", r"\bchmod\b", r"\bwget\b", r"\bcurl\b",
    r">\s*/dev/sd[a-z]", r"mkfs\.\w+", r":\(\)\s*\{.*\};\s*:",  # fork bomb
]

# Prefixes that are transparent wrappers: the next token is the real
# command and must itself be allowlisted.
_WRAPPER_COMMANDS = {"sudo", "timeout", "nice", "ionice", "stdbuf", "env", "nohup", "time"}

# Allowlist for run_command: only these binaries may be invoked. This is
# the primary gate; the denylist above remains as defense-in-depth.
# Anything not listed (interpreters, package managers, shells-as-command,
# file mutators, etc.) is rejected — use the dedicated MCP tools instead.
ALLOWED_COMMANDS = {
    # --- text / file inspection ---
    "cat", "head", "tail", "less", "more", "wc", "sort", "uniq", "cut",
    "awk", "sed", "grep", "egrep", "fgrep", "tr", "strings", "file",
    "diff", "comm", "join", "paste", "column", "fold", "fmt", "nl",
    "tac", "rev", "xxd", "hexdump", "od", "base64", "md5sum", "sha1sum",
    "sha256sum", "sha512sum", "stat", "readlink", "realpath", "basename",
    "dirname", "find", "locate", "which", "whereis", "whatweb",
    # --- directory listing / navigation (read-only usage) ---
    "ls", "pwd", "tree", "du", "df",
    # --- system info ---
    "uname", "hostname", "uptime", "whoami", "id", "groups", "date",
    "cal", "ps", "top", "free", "lscpu", "lsblk", "lspci", "lsusb",
    "env", "printenv", "arch", "nproc", "lsmod", "dmesg",
    # --- network info / recon (read-only) ---
    "ip", "ifconfig", "ss", "netstat", "arp", "route", "ping", "ping6",
    "traceroute", "tracepath", "dig", "nslookup", "host", "whois",
    "arping", "nc", "netcat", "ncat", "socat",
    # --- security tooling (Kali staples, non-mutating) ---
    "nmap", "masscan", "arp-scan", "onesixtyone", "dnsrecon", "dnsenum",
    "nikto", "whatweb", "wafw00f", "sublist3r", "amass", "subfinder",
    "enum4linux", "smbclient", "smbmap", "showmount", "rpcinfo",
    "snmpwalk", "snmpget", "searchsploit", "theHarvester", "exiftool",
    "hash-identifier", "hashid", "wafw00f",
    # --- misc safe utilities ---
    "echo", "printf", "seq", "yes", "true", "false", "sleep", "wait",
    "xargs", "touch", "mkdir", "ln",
    "tar", "gzip", "gunzip", "bzip2", "xz", "zip", "unzip", "7z",
    "git", "jq",
}
# NOTE: interpreters (python, perl, ruby, bash, sh, ...) are deliberately
# NOT allowlisted — they can execute arbitrary code (e.g.
# python3 -c 'os.system("rm -rf /")') and would bypass the denylist.
# Add them back only if you accept that tradeoff.


def _command_segments(command: str) -> list[str]:
    """Split a command string into individual pipeline segments.

    Handles chaining (&&, ||, ;) and command substitution ($(), ``) so
    every invoked binary is checked, not just the first.
    """
    # Normalize chained separators to newlines.
    text = re.sub(r"&&|\|\||;|\n", "\n", command)
    segments: list[str] = []
    # Walk the string, pulling out $() and `` substitutions as their own
    # segments while keeping the surrounding text as segments too.
    pos = 0
    for m in re.finditer(r"\$\(([^()]*)\)|`([^`]*)`", text):
        before = text[pos:m.start()]
        if before.strip():
            segments.extend(s.strip() for s in before.split("\n") if s.strip())
        inner = m.group(1) if m.group(1) is not None else m.group(2)
        if inner and inner.strip():
            segments.append(inner.strip())
        pos = m.end()
    tail = text[pos:]
    if tail.strip():
        segments.extend(s.strip() for s in tail.split("\n") if s.strip())
    return segments


def _segment_leads(segment: str) -> str | None:
    """Extract the leading binary name from one pipeline segment.

    Returns None if the segment is empty or contains no command.
    Skips redirections and wrapper prefixes (sudo, timeout, env, ...).
    """
    # Remove redirections (they don't change which binary runs).
    segment = re.sub(r"\d*>>?|\d*<", " ", segment)
    # Remove pipes within the segment: each side is its own command.
    try:
        tokens = shlex.split(segment, posix=True)
    except ValueError:
        # Unbalanced quotes — fall back to naive splitting; the denylist
        # layer still runs on the raw string afterwards.
        tokens = segment.split()
    if not tokens:
        return None
    # Skip leading variable assignments (FOO=bar cmd ...)
    idx = 0
    while idx < len(tokens) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[idx]):
        idx += 1
    # Skip wrapper prefixes; the wrapped command must also be allowlisted.
    while idx < len(tokens) and os.path.basename(tokens[idx]) in _WRAPPER_COMMANDS:
        idx += 1
        # timeout takes a DURATION argument (e.g. "timeout 10 cmd");
        # nice/ionice take -n N; env may take NAME=VALUE pairs. Skip
        # options and their values until the wrapped command appears.
        while idx < len(tokens):
            tok = tokens[idx]
            if tok.startswith("-"):
                idx += 1  # an option flag
                # flags with separate values (-n 5): skip the value too
                if tok in ("-n", "-i", "-p", "-o", "--adjustment") and idx < len(tokens):
                    idx += 1
            elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tok):
                idx += 1  # env NAME=VALUE
            elif re.match(r"^\d+[smhd]?$", tok):
                idx += 1  # timeout duration like "10" or "90s"
            else:
                break
    if idx >= len(tokens):
        return None
    return os.path.basename(tokens[idx])


def _find_disallowed(command: str) -> str | None:
    """Return the first binary in the command that is not allowlisted."""
    for segment in _command_segments(command):
        for sub in segment.split("|"):
            lead = _segment_leads(sub)
            if lead and lead not in ALLOWED_COMMANDS:
                return lead
    return None


def _find_blocked(command: str) -> str | None:
    """Check every token of the command string against the denylist.

    Quoted strings are stripped first, so words inside quotes
    (e.g. grep 'mkfs', echo "rm") don't trigger false positives.
    The remaining string is split on whitespace and shell metacharacters
    so blocked commands can't be smuggled in via chaining (&&, ;, |)
    or substitution ($(), ``). Regex patterns additionally catch
    variants like mkfs.ext4 and raw-device redirections.
    """
    # Strip quoted strings (single and double) before any matching.
    unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", "", command)

    for token in _SHELL_TOKEN_SPLIT.split(unquoted):
        token = token.strip("'\"")
        if not token:
            continue
        name = os.path.basename(token)  # catches /bin/rm, ./dd, sudo rm, etc.
        if name in BLOCKED_COMMANDS:
            return name
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, unquoted):
            return pattern
    return None


def _tool_env() -> dict[str, str]:
    """Environment nudging language runtimes to stay within the memory limit."""
    env = os.environ.copy()
    env.setdefault("MALLOC_ARENA_MAX", "2")
    if TOOL_MEMORY_MB:
        soft = TOOL_MEMORY_MB * 3 // 4
        env.setdefault("GOMEMLIMIT", f"{soft}MiB")
        env.setdefault("NODE_OPTIONS", f"--max-old-space-size={soft}")
    return env


def _process_tree(root: int) -> set[int]:
    """Return root, its descendants, and members of its process group."""
    children: dict[int, list[int]] = {}
    found = set()
    try:
        entries = os.listdir("/proc")
    except OSError:
        return {root}
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat") as fh:
                # The command name may contain spaces, so split after it.
                fields = fh.read().rpartition(")")[2].split()
        except OSError:
            continue
        pid = int(entry)
        children.setdefault(int(fields[1]), []).append(pid)
        if int(fields[2]) == root:
            found.add(pid)
    pending = [root, *found]
    found.add(root)
    while pending:
        for pid in children.get(pending.pop(), ()):
            if pid not in found:
                found.add(pid)
                pending.append(pid)
    return found


def _tree_memory_mb(root: int) -> int:
    """Private and shared-memory use of a process tree, excluding file pages."""
    total = 0
    for pid in _process_tree(root):
        try:
            with open(f"/proc/{pid}/status") as fh:
                for line in fh:
                    if line.startswith(("RssAnon:", "RssShmem:")):
                        total += int(line.split()[1])
        except (OSError, ValueError, IndexError):
            continue
    return total // 1024


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill a session leader, its group, and detached descendants."""
    # A reaped PID may have been reused, so only walk /proc while it is ours.
    if proc.returncode is None:
        for pid in _process_tree(proc.pid) - {proc.pid}:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass


def _prefer_for_oom(pid: int) -> None:
    """Make the kernel OOM killer pick the tool instead of the MCP server."""
    try:
        with open(f"/proc/{pid}/oom_score_adj", "w") as fh:
            fh.write("1000")
    except OSError:
        pass


def _prune_outputs() -> None:
    try:
        files = sorted(Path(SPOOL_DIR).glob(f"{_OUTPUT_PREFIX}*"), key=lambda p: p.stat().st_mtime)
        for path in files[:-KEPT_OUTPUT_FILES]:
            path.unlink(missing_ok=True)
    except OSError:
        pass


def read_limited(path: str | Path) -> str:
    """Read a report file, truncating it to the output limit.

    A truncated report is copied to the spool directory because callers
    usually delete the original.
    """
    with open(path, "rb") as fh:
        return _bounded_text(fh)


def _bounded_text(fh) -> str:
    """Decode a spooled stream, keeping an overflow copy when it is too large."""
    size = os.fstat(fh.fileno()).st_size
    fh.seek(0)
    data = fh.read(MAX_OUTPUT_BYTES) if MAX_OUTPUT_BYTES else fh.read()
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    text = decoder.decode(data, final=len(data) == size)
    text = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if len(data) == size:
        return text
    location = "<unable to write overflow file>"
    try:
        fd, name = tempfile.mkstemp(prefix=_OUTPUT_PREFIX, suffix=".txt", dir=SPOOL_DIR)
        with os.fdopen(fd, "wb") as out:
            fh.seek(0)
            while chunk := fh.read(1 << 20):
                out.write(chunk)
        location = name
        _prune_outputs()
    except OSError:
        pass
    return (f"{text}\n\n…[truncated: {len(data)} of {size} bytes shown; "
            f"full output written to {location}]")


@contextmanager
def _slot():
    """Wait for a free execution slot; yields an error string on failure."""
    event = cancel_event.get()
    deadline = time.monotonic() + QUEUE_TIMEOUT
    while not _slots.acquire(timeout=0.25):
        if event is not None and event.is_set():
            yield "[error] command cancelled"
            return
        if time.monotonic() >= deadline:
            yield (f"[error] server busy: {MAX_CONCURRENT} tools already running; "
                   "retry later or raise KALI_MCP_MAX_CONCURRENT")
            return
    try:
        yield None
    finally:
        _slots.release()


def _supervise(proc: subprocess.Popen, sinks: dict, timeout: int) -> str | None:
    """Spool output to disk until exit. Returns why the tool was stopped, if it was."""
    event = cancel_event.get()
    deadline = time.monotonic() + timeout
    next_check = 0.0
    spooled = 0
    exited_at = None
    with selectors.DefaultSelector() as selector:
        for pipe in sinks:
            selector.register(pipe, selectors.EVENT_READ)
        while True:
            now = time.monotonic()
            if event is not None and event.is_set():
                return "command cancelled"
            if now >= deadline:
                return f"command timed out after {timeout}s"
            if now >= next_check:
                next_check = now + 0.5
                if TOOL_MEMORY_MB and proc.poll() is None:
                    used = _tree_memory_mb(proc.pid)
                    if used > TOOL_MEMORY_MB:
                        return (f"command stopped: used {used} MB, over the {TOOL_MEMORY_MB} MB limit "
                                "(KALI_MCP_TOOL_MEMORY_MB); reduce its scope or concurrency")
            if not selector.get_map():
                try:
                    proc.wait(timeout=min(0.25, max(0.01, deadline - now)))
                    return None
                except subprocess.TimeoutExpired:
                    continue
            ready = selector.select(0.1)
            for key, _ in ready:
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                sinks[key.fileobj].write(chunk)
                spooled += len(chunk)
            if MAX_SPOOL_BYTES and spooled > MAX_SPOOL_BYTES:
                return (f"command stopped: output exceeded {MAX_SPOOL_BYTES} bytes "
                        "(KALI_MCP_MAX_SPOOL_BYTES); write to a file or narrow the request")
            # A leftover background child may hold the pipes open forever.
            if proc.poll() is not None:
                exited_at = exited_at or now
                if not ready and now - exited_at > 1:
                    return None


def _execute(command, timeout: int, input_data: str | None = None, **popen_args) -> str:
    """Run one command with bounded memory, output, concurrency, and lifetime."""
    with _slot() as busy:
        if busy:
            return busy
        with (tempfile.TemporaryFile(dir=SPOOL_DIR) as out,
              tempfile.TemporaryFile(dir=SPOOL_DIR) as err):
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                # Never inherit stdin: scanners would consume the MCP stream.
                stdin=subprocess.PIPE,
                env=_tool_env(),
                start_new_session=True,
                **popen_args,
            )
            try:
                _prefer_for_oom(proc.pid)
                try:
                    proc.stdin.write((input_data or "").encode())
                    proc.stdin.close()
                except BrokenPipeError:
                    pass
                stopped = _supervise(proc, {proc.stdout: out, proc.stderr: err}, timeout)
            finally:
                _kill_tree(proc)
                proc.wait()
                proc.stdout.close()
                proc.stderr.close()
            out.flush()
            err.flush()
            if stopped or proc.returncode != 0:
                reason = stopped or f"command exited with code {proc.returncode}"
                output = "\n".join(filter(None, (_bounded_text(out), _bounded_text(err))))
                return f"[error] {reason}\n{output}".strip()
            return _bounded_text(out) or _bounded_text(err)


def run_tool(command: list[str], timeout: int = DEFAULT_TIMEOUT, input_data: str = "") -> str:
    executable = os.path.basename(command[0])
    if executable in BLOCKED_COMMANDS:
        return f"[error] command '{executable}' is blocked for safety"

    try:
        return _execute(command, timeout, input_data) or "[info] command produced no output"
    except FileNotFoundError:
        return f"[error] tool '{command[0]}' not found — is it installed?"
    except Exception as e:
        return f"[error] {e}"


def run_bash(command: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    if not command or not command.strip():
        return "[error] command is required"

    # 1. Allowlist check (primary gate): every binary in every segment
    #    (chains, pipelines, substitutions) must be explicitly allowed.
    disallowed = _find_disallowed(command)
    if disallowed:
        return (
            f"[error] command '{disallowed}' is not in the allowed list. "
            f"run_command only permits known-safe tools; use a dedicated MCP tool if one exists."
        )

    # 2. Denylist check (defense-in-depth): blocks destructive patterns
    #    even if something slips into the allowlist later.
    blocked = _find_blocked(command)
    if blocked:
        return f"[error] command '{blocked}' is blocked for safety"

    try:
        output = _execute(command, timeout, shell=True, executable="/bin/bash")
        return output or "[info] command produced no output (exit code 0)"
    except Exception as e:
        return f"[error] {e}"


def require_target(target: str | None) -> str | None:
    if not target or not target.strip():
        return "target is required"
    return None


def start_background(
    command: list[str],
    env: dict | None = None,
    cwd: str | None = None,
    log_file: str = "",
) -> subprocess.Popen:
    """Launch a long-running daemon and return its Popen handle.

    This is the sanctioned gateway (alongside run_tool/run_bash) for
    processes that must outlive a single call — e.g. the OWASP ZAP daemon.
    All direct subprocess usage stays in this module. The child is detached
    into its own session so it survives the caller, with output redirected
    to ``log_file`` (or discarded).
    """
    executable = os.path.basename(command[0])
    if executable in BLOCKED_COMMANDS:
        raise ValueError(f"command '{executable}' is blocked for safety")

    sink = open(log_file, "ab") if log_file else subprocess.DEVNULL
    try:
        proc = subprocess.Popen(
            command,
            stdout=sink,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
            cwd=cwd,
            start_new_session=True,
        )
    except Exception as e:
        raise RuntimeError(f"failed to start background process: {e}") from e
    finally:
        if log_file:
            sink.close()  # child keeps its own duplicate of the fd
    _prefer_for_oom(proc.pid)
    return proc


def stop_background(proc: subprocess.Popen | None, timeout: int = 10) -> bool:
    """Terminate a process started with start_background(). Returns success."""
    if proc is None or proc.poll() is not None:
        return True
    try:
        proc.terminate()
        proc.wait(timeout=timeout)
    except Exception:
        try:
            proc.kill()
            proc.wait(timeout=timeout)
        except Exception:
            return False
    finally:
        _kill_tree(proc)  # browsers and other helpers left in its session
    return True
