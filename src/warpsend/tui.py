"""Textual TUI -- browse files, pick peers, watch progress (v1.9).

    warpsend tui

An optional extra: `pip install warpsend[tui]` (Textual).
The core stays stdlib-only; this module is only imported
when the `tui` command runs.

Layout: a file tree on the left (Enter opens a directory,
Space queues the highlighted file), saved + LAN-discovered
peers on the right, a send queue under the tree, and a
progress bar + transfer log at the bottom.

Sending runs in-process in a worker thread, through
send_tcp's on_progress/on_message hooks, so the progress
bar shows exact percentages and nothing prints to the
terminal behind the app. Receiving runs as a `warpsend
receive` subprocess whose output is piped into the log --
its prints never reach the terminal, so the screen stays
clean. Sends are TCP only (the peer's mode is ignored);
peers come from the config file and from mDNS discovery.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
from typing import ClassVar

from .config import DEFAULT_PORT
from .mdns import browse
from .peers import load_config, resolve_target
from .transfer import _fmt_bytes, send_tcp

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.widgets import (
        Button,
        DirectoryTree,
        Footer,
        Header,
        Label,
        ListItem,
        ListView,
        Log,
        ProgressBar,
    )

    TEXTUAL_AVAILABLE = True
except ImportError:  # pragma: no cover -- textual is an optional extra
    TEXTUAL_AVAILABLE = False

    class _StubApp:
        """Stand-in so this module imports without Textual.

        Instantiating it raises the install hint; the CLI
        checks TEXTUAL_AVAILABLE before it ever gets here.
        With `from __future__ import annotations` above, the
        method annotations below are strings, so only the
        base class and the BINDINGS list need stand-ins.
        """

        def __init__(self, *args, **kwargs):
            raise ImportError("the TUI needs Textual: pip install warpsend[tui]")

    App = _StubApp

    class Binding:
        """Stand-in so the BINDINGS list can be built."""

        def __init__(self, *args, **kwargs):
            pass


def peer_label(peer):
    """One line for the peer list."""
    mode = "tcp" if peer.get("mode", "tcp") == "tcp" else peer["mode"]
    tls = " + TLS" if peer.get("tls") else ""
    src = " (LAN)" if peer.get("source") == "lan" else ""
    return f"{peer['name']} -- {peer['host']}:{peer['port']} {mode}{tls}{src}"


def merge_peers(saved, discovered):
    """Saved peers first, then LAN-discovered ones not already
    saved (matched by name, case-insensitive)."""
    merged = [
        {
            "name": p["name"],
            "host": p["host"],
            "port": p["port"],
            "mode": p.get("mode", "tcp"),
            "tls": p.get("tls", False),
            "fingerprint": p.get("fingerprint"),
            "key_file": p.get("key_file"),
            "source": "saved",
        }
        for p in saved
    ]
    known = {p["name"].lower() for p in merged}
    for d in discovered:
        if d["name"].lower() in known:
            continue
        merged.append(
            {
                "name": d["name"],
                "host": d["host"],
                "port": d["port"],
                "mode": d.get("mode", "tcp"),
                "tls": d.get("tls", False),
                "fingerprint": d.get("fingerprint"),
                "key_file": None,
                "source": "lan",
            }
        )
    return merged


def target_for_peer(peer, config):
    """Resolve a merged peer entry to a send target, the same
    way the CLI resolves --peer / a LAN lookup."""
    if peer["source"] == "saved":
        return resolve_target(config, peer=peer["name"])
    return resolve_target(
        config,
        host=peer["host"],
        port=peer["port"],
        tls=peer["tls"],
        fingerprint=peer["fingerprint"],
    )


def _key_for_target(target):
    """Shared secret for a target: key file, then env."""
    key_file = target.get("key_file")
    if key_file:
        try:
            with open(os.path.expanduser(key_file)) as f:
                return f.read().strip()
        except OSError:
            return None
    return os.environ.get("WARPSEND_KEY")


class WarpSendApp(App):
    """The WarpSend TUI."""

    TITLE = "WarpSend"
    CSS = """
    #main { height: 1fr; }
    #files-pane { width: 58%; border: solid $accent; }
    #peers-pane { width: 42%; border: solid $accent; }
    #bottom { height: 11; border: solid $accent; }
    DirectoryTree { height: 1fr; }
    #queue-list { height: 5; }
    #peer-list { height: 1fr; }
    #log { height: 1fr; }
    #buttons { height: 3; }
    """

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("q", "quit", "Quit"),
        Binding("d", "discover", "Discover"),
        Binding("s", "send", "Send"),
        Binding("r", "receiver", "Receiver"),
        Binding("u", "up", "Up a directory"),
        Binding("space", "queue_highlighted", "Queue file"),
    ]

    def __init__(self, start_dir=".", port=None, outdir=None):
        super().__init__()
        self.start_dir = os.path.abspath(start_dir)
        self.port = port or DEFAULT_PORT
        self.outdir = outdir or "./received"
        self.queue = []  # file paths to send
        self.peers = []  # merged peer entries
        self.selected_peer = None  # index into self.peers
        self.config = None
        self.receiver_proc = None
        self.receiver_thread = None
        self.sending = False

    # -- layout ---------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main"):
            with Vertical(id="files-pane"):
                yield Label("Files (Enter: open, Space: queue)")
                yield DirectoryTree(self.start_dir, id="tree")
                yield Label("Send queue (click an item to remove it)")
                yield ListView(id="queue-list")
            with Vertical(id="peers-pane"):
                yield Label("Peers (saved + LAN)")
                yield ListView(id="peer-list")
                with Horizontal(id="buttons"):
                    yield Button("Discover", id="btn-discover")
                    yield Button("Send", id="btn-send")
                    yield Button("Start receiver", id="btn-receiver")
                    yield Button("Up", id="btn-up")
        with Vertical(id="bottom"):
            yield Label("Idle", id="status")
            yield ProgressBar(total=100, show_eta=False, id="progress")
            yield Log(id="log")
        yield Footer()

    def on_mount(self):
        self.log_line("WarpSend TUI -- Space queues a file, S sends it to the selected peer.")
        try:
            self.config = load_config()
        except (OSError, ValueError) as e:
            self.log_line(f"could not load config: {e}")
            self.config = {}
        self._refresh_peers([])
        self.run_worker(self._discover_worker, thread=True)

    # -- helpers ----------------------------------------------------------

    def log_line(self, text):
        self.query_one("#log", Log).write_line(text)

    def set_status(self, text):
        self.query_one("#status", Label).update(text)

    def set_progress(self, done, total):
        bar = self.query_one("#progress", ProgressBar)
        bar.update(total=100, progress=(done / total * 100 if total else 0))

    def _refresh_peers(self, discovered):
        saved = []
        if self.config:
            saved = [
                {"name": name, **info} for name, info in (self.config.get("peers") or {}).items()
            ]
        self.peers = merge_peers(saved, discovered)
        peer_list = self.query_one("#peer-list", ListView)
        peer_list.clear()
        for peer in self.peers:
            peer_list.append(ListItem(Label(peer_label(peer))))
        if self.peers and self.selected_peer is None:
            self.selected_peer = 0
            peer_list.index = 0
        self._update_send_label()

    def _update_send_label(self):
        if self.sending:
            return  # the send worker owns the status line meanwhile
        peer = self.peers[self.selected_peer] if self.selected_peer is not None else None
        self.set_status(
            f"Send to: {peer['name'] if peer else '(select a peer)'} -- "
            f"{len(self.queue)} file(s) queued"
        )

    def _refresh_queue(self):
        queue_list = self.query_one("#queue-list", ListView)
        queue_list.clear()
        for path in self.queue:
            try:
                size = os.path.getsize(path)
            except OSError:
                size = 0
            queue_list.append(ListItem(Label(f"{os.path.basename(path)} ({_fmt_bytes(size)})")))
        self._update_send_label()

    def _queue_file(self, path):
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            return
        if path in self.queue:
            return
        self.queue.append(path)
        self._refresh_queue()
        self.log_line(f"queued {os.path.basename(path)}")

    # -- file tree --------------------------------------------------------

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected):
        self._queue_file(str(event.path))

    def action_queue_highlighted(self):
        tree = self.query_one("#tree", DirectoryTree)
        node = tree.cursor_node
        if node is None or node.data is None:
            return
        path = node.data.path
        if os.path.isdir(path):
            return
        self._queue_file(str(path))

    def action_up(self):
        tree = self.query_one("#tree", DirectoryTree)
        parent = os.path.dirname(tree.path)
        if parent and parent != tree.path:
            tree.path = parent

    # -- peers ------------------------------------------------------------

    def on_list_view_selected(self, event: ListView.Selected):
        if event.list_view.id == "peer-list":
            self.selected_peer = event.list_view.index
            peer = self.peers[self.selected_peer]
            self.log_line(f"selected peer {peer['name']} ({peer['host']}:{peer['port']})")
            self._update_send_label()
        elif event.list_view.id == "queue-list":
            idx = event.list_view.index
            if idx is not None and 0 <= idx < len(self.queue):
                removed = self.queue.pop(idx)
                self.log_line(f"removed {os.path.basename(removed)} from the queue")
                self._refresh_queue()

    def _discover_worker(self):
        try:
            found = browse(timeout=2.5)
        except OSError as e:
            self.call_from_thread(self.log_line, f"mDNS is not available here: {e}")
            return
        if found:
            self.call_from_thread(self.log_line, f"discovered {len(found)} receiver(s) on the LAN")
        self.call_from_thread(self._refresh_peers, found)

    def action_discover(self):
        self.log_line("discovering receivers on the LAN ...")
        self.run_worker(self._discover_worker, thread=True)

    # -- sending ----------------------------------------------------------

    def action_send(self):
        if self.sending:
            self.log_line("already sending -- wait for the current batch")
            return
        if self.selected_peer is None or not self.peers:
            self.log_line("no peer selected -- pick one from the peer list first")
            return
        if not self.queue:
            self.log_line("nothing queued -- highlight a file and press Space")
            return
        self.sending = True
        self.run_worker(self._send_worker, thread=True)

    def _send_worker(self):
        peer = self.peers[self.selected_peer]
        try:
            target = target_for_peer(peer, self.config or {})
        except (ValueError, KeyError, OSError) as e:
            self.call_from_thread(self.log_line, f"could not resolve peer {peer['name']}: {e}")
            self.call_from_thread(self._send_done)
            return
        key = _key_for_target(target)
        files = list(self.queue)
        for i, path in enumerate(files, 1):
            name = os.path.basename(path)
            self.call_from_thread(self.set_status, f"sending {name} ({i}/{len(files)})")
            self.call_from_thread(self.set_progress, 0, 1)
            ok = send_tcp(
                target["host"],
                target["port"],
                path,
                key=key,
                tls=target["tls"],
                fingerprint=target["fingerprint"],
                on_progress=lambda d, t: self.call_from_thread(self.set_progress, d, t),
                on_message=lambda m: self.call_from_thread(self.log_line, m),
            )
            if ok:
                self.call_from_thread(self._remove_from_queue, path)
                self.call_from_thread(self.log_line, f"sent {name} -- verified by peer")
            else:
                self.call_from_thread(self.log_line, f"failed to send {name} -- kept in queue")
                break
        self.call_from_thread(self.set_progress, 0, 1)
        self.call_from_thread(self.set_status, "Idle")
        self.call_from_thread(self._send_done)

    def _remove_from_queue(self, path):
        if path in self.queue:
            self.queue.remove(path)
        self._refresh_queue()

    def _send_done(self):
        self.sending = False
        self._update_send_label()

    # -- receiver ---------------------------------------------------------

    def action_receiver(self):
        if self.receiver_proc is not None:
            self._stop_receiver()
        else:
            self._start_receiver()

    def _start_receiver(self):
        cmd = [
            sys.executable,
            "-m",
            "warpsend",
            "--no-banner",
            "receive",
            "--port",
            str(self.port),
            "--outdir",
            self.outdir,
        ]
        try:
            self.receiver_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
        except OSError as e:
            self.log_line(f"could not start receiver: {e}")
            return
        self.query_one("#btn-receiver", Button).label = "Stop receiver"
        self.log_line(f"receiver started on port {self.port}, saving to {self.outdir}")
        self.receiver_thread = threading.Thread(target=self._receiver_reader, daemon=True)
        self.receiver_thread.start()

    def _receiver_reader(self):
        proc = self.receiver_proc
        try:
            for raw_line in proc.stdout:
                text = raw_line.rstrip("\n")
                if not text:
                    continue
                # The receiver's own progress bar would spam the
                # log; skip those lines.
                if "[#" in text and "%" in text:
                    continue
                self.call_from_thread(self.log_line, f"[recv] {text}")
        except (OSError, ValueError):
            pass

    def _stop_receiver(self):
        proc = self.receiver_proc
        self.receiver_proc = None
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    proc.kill()
                except OSError:
                    pass
        self.query_one("#btn-receiver", Button).label = "Start receiver"
        self.log_line("receiver stopped")

    # -- buttons ----------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-discover":
            self.action_discover()
        elif event.button.id == "btn-send":
            self.action_send()
        elif event.button.id == "btn-receiver":
            self.action_receiver()
        elif event.button.id == "btn-up":
            self.action_up()

    # -- exit -------------------------------------------------------------

    def action_quit(self):
        if self.receiver_proc is not None:
            self._stop_receiver()
        self.exit()
