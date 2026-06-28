#!/usr/bin/env python3
"""
connmon_edr.py
Lightweight Linux connection monitor with eBPF outbound connect detection.

Run as root.
Requires:
    sudo apt install python3-bpfcc
    pip install textual
"""

from __future__ import annotations
import subprocess
import socket
import re
import os
import threading
import queue
import ctypes
from datetime import datetime
from pathlib import Path
from socket import inet_ntop, AF_INET
from struct import pack

# =========================
# Globals
# =========================

CONNECT_EVENTS = queue.Queue()
PID_CACHE = {}

# =========================
# Utilities
# =========================

def resolve_binary_path(pid: str) -> str:
    if not pid:
        return ""
    if pid in PID_CACHE:
        return PID_CACHE[pid]
    try:
        path = os.readlink(f"/proc/{pid}/exe")
        PID_CACHE[pid] = path
        return path
    except:
        return ""

def _run(cmd: str) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, shell=True).stdout
    except:
        return ""

# =========================
# SS Parsers
# =========================

def parse_ss_tcp():
    lines = _run("ss -tnp").splitlines()
    results = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue

        state = parts[0]
        local = parts[3]
        remote = parts[4]

        pid = ""
        process = ""

        for p in parts[5:]:
            m = re.search(r'"([^"]+)",pid=(\d+)', p)
            if m:
                process = m.group(1)
                pid = m.group(2)
                break

        results.append({
            "state": state,
            "local": local,
            "remote": remote,
            "pid": pid,
            "process": process
        })

    return results


def parse_ss_udp():
    lines = _run("ss -unp").splitlines()
    results = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue

        state = parts[0]
        local = parts[3]
        remote = parts[4]

        pid = ""
        process = ""

        for p in parts[5:]:
            m = re.search(r'"([^"]+)",pid=(\d+)', p)
            if m:
                process = m.group(1)
                pid = m.group(2)
                break

        results.append({
            "state": state,
            "local": local,
            "remote": remote,
            "pid": pid,
            "process": process
        })

    return results


def parse_listeners():
    listeners = []

    for proto, cmd in [("tcp", "ss -tlnp"), ("udp", "ss -ulnp")]:
        lines = _run(cmd).splitlines()

        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue

            local = parts[3]
            port = local.rsplit(":", 1)[-1] if ":" in local else local

            pid = ""
            process = ""

            for p in parts[4:]:
                m = re.search(r'"([^"]+)",pid=(\d+)', p)
                if m:
                    process = m.group(1)
                    pid = m.group(2)
                    break

            listeners.append({
                "proto": proto,
                "local": local,
                "port": port,
                "pid": pid,
                "process": process,
                "binary": resolve_binary_path(pid)
            })

    return listeners


def parse_sessions():
    lines = _run("who -u").splitlines()
    sessions = []

    for line in lines:
        parts = line.split()
        if len(parts) < 5:
            continue

        sessions.append({
            "user": parts[0],
            "tty": parts[1],
            "time": f"{parts[2]} {parts[3]}",
            "pid": parts[-1] if parts[-1].isdigit() else ""
        })

    return sessions

# =========================
# eBPF Connect Monitor
# =========================

def start_ebpf_monitor():
    from bcc import BPF

    bpf_program = r"""
    #include <uapi/linux/ptrace.h>
    #include <linux/sched.h>
    #include <net/sock.h>

    struct event_t {
        u32 pid;
        u32 daddr;
        u16 dport;
        char comm[TASK_COMM_LEN];
    };

    BPF_PERF_OUTPUT(events);

    int trace_connect(struct pt_regs *ctx, struct sock *sk) {
        struct event_t event = {};
        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.daddr = sk->__sk_common.skc_daddr;
        event.dport = ntohs(sk->__sk_common.skc_dport);
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        events.perf_submit(ctx, &event, sizeof(event));
        return 0;
    }
    """

    b = BPF(text=bpf_program)
    b.attach_kprobe(event="tcp_connect", fn_name="trace_connect")

    class Event(ctypes.Structure):
        _fields_ = [
            ("pid", ctypes.c_uint),
            ("daddr", ctypes.c_uint),
            ("dport", ctypes.c_ushort),
            ("comm", ctypes.c_char * 16),
        ]

    def handle_event(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(Event)).contents

        try:
            ip = inet_ntop(AF_INET, pack("I", event.daddr))
        except:
            ip = "unknown"

        CONNECT_EVENTS.put({
            "time": datetime.now().strftime("%H:%M:%S"),
            "pid": event.pid,
            "comm": event.comm.decode(),
            "ip": ip,
            "port": event.dport,
            "exe": resolve_binary_path(str(event.pid))
        })

    b["events"].open_perf_buffer(handle_event)

    while True:
        b.perf_buffer_poll()

# =========================
# TEXTUAL UI
# =========================

from textual.app import App, ComposeResult
from textual.widgets import Static

class ConnMonApp(App):
    TITLE = "connmon EDR"

    def __init__(self):
        super().__init__()
        threading.Thread(target=start_ebpf_monitor, daemon=True).start()
        self._connect_history = []

    def compose(self) -> ComposeResult:
        yield Static("Loading...", id="main")

    def on_mount(self):
        self.set_interval(2, self.refresh_data)

    def refresh_data(self):
        tcp = parse_ss_tcp()
        udp = parse_ss_udp()
        listeners = parse_listeners()
        sessions = parse_sessions()

        while not CONNECT_EVENTS.empty():
            self._connect_history.append(CONNECT_EVENTS.get())

        self._connect_history = self._connect_history[-50:]

        lines = []

        # ===== Outbound Connect Events =====
        lines.append("[bold cyan]Outbound Connect Events[/bold cyan]")
        lines.append("-" * 100)

        for e in reversed(self._connect_history):
            dest = f"{e['ip']}:{e['port']}"
            lines.append(
                f"[bold red]{e['time']} PID={e['pid']} "
                f"{e['comm']} -> {dest} {e['exe']}[/bold red]"
            )

        # ===== Listeners =====
        lines.append("\n[bold cyan]Listeners[/bold cyan]")
        lines.append("-" * 100)

        for l in listeners:
            lines.append(
                f"{l['proto']} {l['local']} PID={l['pid']} "
                f"{l['process']} {l['binary']}"
            )

        # ===== TCP Connections (UPDATED SECTION) =====
        lines.append("\n[bold cyan]TCP Connections[/bold cyan]")
        lines.append("-" * 100)

        for c in tcp:
            binary = resolve_binary_path(c["pid"])
            lines.append(
                f"{c['state']} {c['local']} -> {c['remote']} "
                f"PID={c['pid']} {binary}"
            )

        # ===== UDP Connections =====
        lines.append("\n[bold cyan]UDP Connections[/bold cyan]")
        lines.append("-" * 100)

        for c in udp:
            binary = resolve_binary_path(c["pid"])
            lines.append(
                f"{c['state']} {c['local']} -> {c['remote']} "
                f"PID={c['pid']} {binary}"
            )

        # ===== Sessions =====
        lines.append("\n[bold cyan]Sessions[/bold cyan]")
        lines.append("-" * 100)

        for s in sessions:
            lines.append(
                f"{s['user']} {s['tty']} {s['time']} PID={s['pid']}"
            )

        self.query_one("#main", Static).update("\n".join(lines))


# =========================
# MAIN
# =========================

if __name__ == "__main__":
    ConnMonApp().run()
