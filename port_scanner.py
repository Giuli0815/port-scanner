import customtkinter as ctk
import socket
import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor

# ── theme ──────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

ACCENT   = "#00D4A0"
BG_DARK  = "#0D1117"
BG_CARD  = "#161B22"
BG_INPUT = "#1C2128"
TEXT_DIM = "#8B949E"
TEXT_FG  = "#E6EDF3"
RED      = "#F85149"
YELLOW   = "#E3B341"

# ── service map ────────────────────────────────────────────────────────────────
SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 119: "NNTP", 123: "NTP", 135: "RPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 194: "IRC", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 515: "LPD", 587: "SMTP",
    631: "IPP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL", 2222: "SSH-Alt",
    3000: "Dev-Server", 3306: "MySQL", 3389: "RDP", 3690: "SVN",
    4000: "ICQ", 4444: "Metasploit", 5000: "Flask/UPnP", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM", 6379: "Redis", 6443: "K8s-API",
    6667: "IRC", 8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9090: "Cockpit", 9200: "Elasticsearch", 9300: "ES-Cluster",
    27017: "MongoDB", 27018: "MongoDB", 28017: "MongoDB-Web",
}

# ── IP quick-targets per mode ──────────────────────────────────────────────────
IP_PRESETS = {
    "Local": [
        ("Localhost",   "127.0.0.1"),
        ("Gateway",     "192.168.1.1"),
        ("LAN /24",     "192.168.0.1"),
    ],
    "Public": [
        ("Google DNS",  "8.8.8.8"),
        ("Cloudflare",  "1.1.1.1"),
        ("OpenDNS",     "208.67.222.222"),
    ],
    "IPv6": [
        ("Loopback",    "::1"),
        ("Google",      "2001:4860:4860::8888"),
        ("Cloudflare",  "2606:4700:4700::1111"),
    ],
}


def get_service(port: int) -> str:
    if port in SERVICES:
        return SERVICES[port]
    try:
        return socket.getservbyport(port)
    except Exception:
        return "Unknown"


def resolve_host(host: str) -> tuple[str, int]:
    """Return (resolved_ip, AF_INET or AF_INET6). Raises OSError on failure."""
    host = host.strip()
    # Try IPv6 literal first
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return host, socket.AF_INET6
    except OSError:
        pass
    # Try IPv4 literal
    try:
        socket.inet_pton(socket.AF_INET, host)
        return host, socket.AF_INET
    except OSError:
        pass
    # Hostname — resolve, prefer IPv6 if present
    results = socket.getaddrinfo(host, None)
    for fam, *_, addr in results:
        if fam == socket.AF_INET6:
            return addr[0], socket.AF_INET6
    for fam, *_, addr in results:
        if fam == socket.AF_INET:
            return addr[0], socket.AF_INET
    raise OSError(f"Cannot resolve {host!r}")


def scan_port(host: str, port: int, timeout: float,
              family: int) -> tuple[int, bool, str]:
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            addr = (host, port, 0, 0) if family == socket.AF_INET6 else (host, port)
            open_ = s.connect_ex(addr) == 0
    except Exception:
        open_ = False
    return port, open_, get_service(port) if open_ else ""


# ── main app ───────────────────────────────────────────────────────────────────
class PortScannerApp(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("Port Scanner")
        self.geometry("960x720")
        self.minsize(820, 620)
        self.configure(fg_color=BG_DARK)

        try:
            import ctypes, sys, os
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("portscanner.app")
            base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
            self.iconbitmap(os.path.join(base, "icon.ico"))
        except Exception:
            pass

        self._scan_thread: threading.Thread | None = None
        self._stop_event  = threading.Event()
        self._result_queue: queue.Queue = queue.Queue()
        self._open_count  = 0
        self._total_ports = 0
        self._scanned     = 0
        self._ip_family   = socket.AF_INET
        self._last_target = ""

        self._build_ui()
        self._poll_results()

    # ── UI ─────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        self._build_header()
        self._build_body()
        self._build_statusbar()

    # header ───────────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=0, height=60)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_propagate(False)
        hdr.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(hdr, text=" ⚡ ", font=("Segoe UI", 22),
                     text_color=ACCENT).grid(row=0, column=0, padx=(16, 0), pady=10)
        ctk.CTkLabel(hdr, text="Port Scanner",
                     font=("Segoe UI Semibold", 18, "bold"),
                     text_color=TEXT_FG).grid(row=0, column=1, padx=8, sticky="w")
        ctk.CTkLabel(hdr, text="Multithreaded TCP Network Reconnaissance",
                     font=("Segoe UI", 11),
                     text_color=TEXT_DIM).grid(row=0, column=2, padx=(0, 20), sticky="e")

    # body ─────────────────────────────────────────────────────────────────────
    def _build_body(self):
        body = ctk.CTkFrame(self, fg_color=BG_DARK)
        body.grid(row=1, column=0, sticky="nsew", padx=16, pady=12)
        body.grid_columnconfigure(0, weight=0, minsize=290)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)
        self._build_sidebar(body)
        self._build_results(body)

    # sidebar ──────────────────────────────────────────────────────────────────
    def _build_sidebar(self, parent):
        side = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=12)
        side.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        side.grid_columnconfigure(0, weight=1)

        def section(text):
            ctk.CTkLabel(side, text=text, font=("Segoe UI", 10, "bold"),
                         text_color=TEXT_DIM).pack(anchor="w", padx=16, pady=(14, 3))

        # ── TARGET ────────────────────────────────────────────────────────────
        section("TARGET")

        # mode segmented button
        self._mode_btn = ctk.CTkSegmentedButton(
            side, values=["Local", "Public", "IPv6"],
            font=("Segoe UI", 12), corner_radius=8,
            fg_color=BG_INPUT, selected_color=ACCENT,
            selected_hover_color="#00B88A",
            unselected_color=BG_INPUT, unselected_hover_color="#21262D",
            text_color=TEXT_FG, text_color_disabled=TEXT_DIM,
            command=self._on_mode_change)
        self._mode_btn.pack(fill="x", padx=16, pady=(0, 6))
        self._mode_btn.set("Local")

        # host entry
        ctk.CTkLabel(side, text="Host / IP", font=("Segoe UI", 12),
                     text_color=TEXT_FG).pack(anchor="w", padx=16, pady=(4, 1))
        self._host_entry = ctk.CTkEntry(
            side, placeholder_text="e.g. 192.168.1.1",
            fg_color=BG_INPUT, border_color="#30363D",
            text_color=TEXT_FG, height=36, corner_radius=8)
        self._host_entry.pack(fill="x", padx=16, pady=(0, 4))

        # quick-target buttons (container rebuilt on mode change)
        self._preset_container = ctk.CTkFrame(side, fg_color="transparent")
        self._preset_container.pack(fill="x", padx=16, pady=(0, 2))
        self._refresh_presets("Local")

        # ── PORT RANGE ────────────────────────────────────────────────────────
        section("PORT RANGE")
        port_row = ctk.CTkFrame(side, fg_color="transparent")
        port_row.pack(fill="x", padx=16, pady=(2, 2))
        port_row.grid_columnconfigure((0, 2), weight=1)

        ctk.CTkLabel(port_row, text="Start", font=("Segoe UI", 12),
                     text_color=TEXT_FG).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(port_row, text="End", font=("Segoe UI", 12),
                     text_color=TEXT_FG).grid(row=0, column=2, sticky="w", padx=(10, 0))

        self._port_start = ctk.CTkEntry(port_row, width=90, fg_color=BG_INPUT,
                                         border_color="#30363D", text_color=TEXT_FG,
                                         height=34, corner_radius=8)
        self._port_start.grid(row=1, column=0, sticky="ew")
        self._port_start.insert(0, "1")

        ctk.CTkLabel(port_row, text="->", text_color=TEXT_DIM,
                     font=("Segoe UI", 13)).grid(row=1, column=1, padx=4)

        self._port_end = ctk.CTkEntry(port_row, width=90, fg_color=BG_INPUT,
                                       border_color="#30363D", text_color=TEXT_FG,
                                       height=34, corner_radius=8)
        self._port_end.grid(row=1, column=2, sticky="ew")
        self._port_end.insert(0, "1024")

        preset_row = ctk.CTkFrame(side, fg_color="transparent")
        preset_row.pack(fill="x", padx=16, pady=(6, 0))
        for label, s, e in [("Top 100", "1", "100"),
                              ("Well-known", "1", "1024"),
                              ("All ports", "1", "65535")]:
            ctk.CTkButton(preset_row, text=label, width=80, height=26,
                          fg_color=BG_INPUT, hover_color="#21262D",
                          text_color=TEXT_DIM, font=("Segoe UI", 11), corner_radius=6,
                          command=lambda s=s, e=e: self._apply_port_preset(s, e)
                          ).pack(side="left", padx=(0, 6))

        # ── SETTINGS ──────────────────────────────────────────────────────────
        section("SETTINGS")
        self._timeout_slider, _ = self._build_slider(
            side, "Timeout (s)", 0.1, 3.0, 0.5, 0.1)
        self._threads_slider, _ = self._build_slider(
            side, "Threads", 10, 500, 100, 10, integer=True)

        # ── ACTIONS ───────────────────────────────────────────────────────────
        self._scan_btn = ctk.CTkButton(
            side, text="   Start Scan", height=42, corner_radius=10,
            font=("Segoe UI Semibold", 14, "bold"),
            fg_color=ACCENT, hover_color="#00B88A", text_color="#0D1117",
            command=self._start_scan)
        self._scan_btn.pack(fill="x", padx=16, pady=(18, 6))

        self._stop_btn = ctk.CTkButton(
            side, text="   Stop", height=34, corner_radius=10,
            font=("Segoe UI", 13), fg_color=BG_INPUT,
            hover_color="#21262D", text_color=RED,
            border_color=RED, border_width=1,
            state="disabled", command=self._stop_scan)
        self._stop_btn.pack(fill="x", padx=16, pady=(0, 16))

    def _refresh_presets(self, mode: str):
        for w in self._preset_container.winfo_children():
            w.destroy()
        presets = IP_PRESETS.get(mode, [])
        # 3-column grid so buttons always wrap — never push the sidebar wider
        self._preset_container.grid_columnconfigure((0, 1, 2), weight=1)
        for i, (label, ip) in enumerate(presets):
            row, col = divmod(i, 3)
            ctk.CTkButton(
                self._preset_container, text=label, height=24,
                fg_color="#21262D", hover_color="#30363D",
                text_color=ACCENT, font=("Segoe UI", 10), corner_radius=6,
                command=lambda v=ip: self._fill_host(v)
            ).grid(row=row, column=col, sticky="ew", padx=(0, 4), pady=2)

    def _on_mode_change(self, mode: str):
        self._refresh_presets(mode)
        placeholders = {
            "Local":   "e.g. 192.168.1.1",
            "Public":  "e.g. 8.8.8.8 or domain",
            "IPv6":    "e.g. 2001:db8::1",
        }
        self._host_entry.configure(placeholder_text=placeholders[mode])

    def _fill_host(self, ip: str):
        self._host_entry.delete(0, "end")
        self._host_entry.insert(0, ip)

    def _build_slider(self, parent, label, from_, to, default, step, integer=False):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="x", padx=16, pady=(4, 2))

        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.pack(fill="x")
        ctk.CTkLabel(top, text=label, font=("Segoe UI", 12),
                     text_color=TEXT_FG).pack(side="left")
        val_label = ctk.CTkLabel(top,
                                  text=str(int(default)) if integer else f"{default:.1f}",
                                  font=("Segoe UI Semibold", 12), text_color=ACCENT)
        val_label.pack(side="right")

        def update(v):
            snapped = round(float(v) / step) * step
            val_label.configure(text=str(int(snapped)) if integer else f"{snapped:.1f}")

        slider = ctk.CTkSlider(
            frame, from_=from_, to=to,
            number_of_steps=int((to - from_) / step),
            progress_color=ACCENT, button_color=ACCENT,
            button_hover_color="#00B88A", command=update)
        slider.set(default)
        slider.pack(fill="x", pady=(2, 0))
        return slider, val_label

    # results panel ────────────────────────────────────────────────────────────
    def _build_results(self, parent):
        right = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=12)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(3, weight=1)   # scroll frame

        # ── stats bar (auto-height, no grid_propagate(False)) ─────────────────
        stats = ctk.CTkFrame(right, fg_color=BG_INPUT, corner_radius=8)
        stats.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 4))
        stats.grid_columnconfigure((0, 1, 2, 3), weight=1)

        def stat_cell(col, label, color=TEXT_DIM):
            f = ctk.CTkFrame(stats, fg_color="transparent")
            f.grid(row=0, column=col, sticky="nsew", padx=2, pady=8)
            num = ctk.CTkLabel(f, text="–",
                               font=("Segoe UI Semibold", 20, "bold"),
                               text_color=color)
            num.pack()
            ctk.CTkLabel(f, text=label, font=("Segoe UI", 9),
                         text_color=TEXT_DIM).pack()
            return num

        self._stat_open   = stat_cell(0, "Open Ports",    ACCENT)
        self._stat_closed = stat_cell(1, "Closed",         TEXT_DIM)
        self._stat_total  = stat_cell(2, "Total Scanned",  TEXT_FG)
        self._stat_time   = stat_cell(3, "Elapsed",        TEXT_FG)

        # ── IP version badge ──────────────────────────────────────────────────
        self._ip_badge = ctk.CTkLabel(stats, text="IPv4", width=40, height=18,
                                       font=("Segoe UI", 9, "bold"),
                                       fg_color="#21262D", corner_radius=4,
                                       text_color=TEXT_DIM)
        self._ip_badge.grid(row=0, column=4, padx=(0, 8), pady=8, sticky="e")

        # ── progress bar ──────────────────────────────────────────────────────
        self._progress = ctk.CTkProgressBar(right, progress_color=ACCENT,
                                             fg_color=BG_INPUT, height=4,
                                             corner_radius=2)
        self._progress.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 4))
        self._progress.set(0)

        # ── table header ──────────────────────────────────────────────────────
        header = ctk.CTkFrame(right, fg_color=BG_INPUT, corner_radius=6, height=30)
        header.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 2))
        header.grid_propagate(False)
        header.grid_columnconfigure((0, 1, 2), weight=1)
        for col, text in enumerate(["Port", "Status", "Service"]):
            ctk.CTkLabel(header, text=text, font=("Segoe UI", 10, "bold"),
                         text_color=TEXT_DIM, anchor="w"
                         ).grid(row=0, column=col, sticky="w", padx=14, pady=5)

        # ── scrollable results ────────────────────────────────────────────────
        self._result_frame = ctk.CTkScrollableFrame(
            right, fg_color="transparent", corner_radius=0)
        self._result_frame.grid(row=3, column=0, sticky="nsew", padx=12, pady=(0, 4))

        # ── toolbar (clear + export) ──────────────────────────────────────────
        toolbar = ctk.CTkFrame(right, fg_color="transparent")
        toolbar.grid(row=4, column=0, sticky="e", padx=12, pady=(0, 8))

        ctk.CTkButton(toolbar, text="Export .txt", height=28, width=90,
                      corner_radius=6, fg_color=BG_INPUT, hover_color="#21262D",
                      text_color=TEXT_DIM, font=("Segoe UI", 11),
                      command=self._export_results).pack(side="left", padx=(0, 6))
        ctk.CTkButton(toolbar, text="Clear", height=28, width=70,
                      corner_radius=6, fg_color=BG_INPUT, hover_color="#21262D",
                      text_color=TEXT_DIM, font=("Segoe UI", 11),
                      command=self._clear_results).pack(side="left")

    # statusbar ────────────────────────────────────────────────────────────────
    def _build_statusbar(self):
        bar = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=0, height=26)
        bar.grid(row=2, column=0, sticky="ew")
        bar.grid_propagate(False)
        self._status_label = ctk.CTkLabel(bar, text="Ready",
                                           font=("Segoe UI", 11), text_color=TEXT_DIM)
        self._status_label.pack(side="left", padx=16)

    # ── helpers ────────────────────────────────────────────────────────────────

    def _apply_port_preset(self, start, end):
        self._port_start.delete(0, "end"); self._port_start.insert(0, start)
        self._port_end.delete(0, "end");   self._port_end.insert(0, end)

    def _set_status(self, text, color=TEXT_DIM):
        self._status_label.configure(text=text, text_color=color)

    def _add_result_row(self, port: int, open_: bool, service: str):
        row = ctk.CTkFrame(self._result_frame, fg_color="transparent", height=30)
        row.pack(fill="x", pady=1)
        row.grid_columnconfigure((0, 1, 2), weight=1)

        color = ACCENT if open_ else TEXT_DIM
        ctk.CTkLabel(row, text=str(port), font=("Consolas", 13),
                     text_color=color, anchor="w"
                     ).grid(row=0, column=0, sticky="w", padx=14)
        ctk.CTkLabel(row, text="● Open" if open_ else "○ Closed",
                     font=("Segoe UI", 11), text_color=color, anchor="w"
                     ).grid(row=0, column=1, sticky="w", padx=14)
        ctk.CTkLabel(row, text=service or "–", font=("Segoe UI", 11),
                     text_color=TEXT_FG if open_ else TEXT_DIM, anchor="w"
                     ).grid(row=0, column=2, sticky="w", padx=14)

        ctk.CTkFrame(self._result_frame, fg_color="#21262D", height=1).pack(fill="x")

    def _clear_results(self):
        for w in self._result_frame.winfo_children():
            w.destroy()
        self._open_count = self._scanned = 0
        self._progress.set(0)
        for lbl in (self._stat_open, self._stat_closed,
                    self._stat_total, self._stat_time):
            lbl.configure(text="–")
        self._set_status("Ready")

    def _export_results(self):
        import tkinter.filedialog as fd
        rows = [w for w in self._result_frame.winfo_children()
                if isinstance(w, ctk.CTkFrame) and w.winfo_height() > 1]
        if not rows:
            self._set_status("Nothing to export.", YELLOW)
            return
        path = fd.asksaveasfilename(defaultextension=".txt",
                                    filetypes=[("Text", "*.txt"), ("All", "*.*")],
                                    title="Save scan results")
        if not path:
            return
        lines = [f"Port Scanner results — {time.strftime('%Y-%m-%d %H:%M:%S')}",
                 f"Target: {self._last_target}  |  Family: "
                 f"{'IPv6' if self._ip_family == socket.AF_INET6 else 'IPv4'}", ""]
        for w in rows:
            children = w.winfo_children()
            if len(children) >= 3:
                parts = [c.cget("text") for c in children]
                lines.append("  ".join(parts))
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        self._set_status(f"Exported to {path}", ACCENT)

    # ── scan ───────────────────────────────────────────────────────────────────

    def _start_scan(self):
        host = self._host_entry.get().strip()
        if not host:
            self._set_status("Enter a host or IP address.", RED); return

        try:
            start_port = int(self._port_start.get())
            end_port   = int(self._port_end.get())
            if not (1 <= start_port <= end_port <= 65535):
                raise ValueError
        except ValueError:
            self._set_status("Port range must be 1–65535 with start <= end.", RED)
            return

        try:
            ip, family = resolve_host(host)
        except OSError:
            self._set_status(f"Cannot resolve '{host}'.", RED)
            return

        self._ip_family   = family
        self._last_target = host
        is_v6 = family == socket.AF_INET6
        self._ip_badge.configure(
            text="IPv6" if is_v6 else "IPv4",
            text_color=YELLOW if is_v6 else ACCENT,
            fg_color="#21262D")

        timeout = float(self._timeout_slider.get())
        threads = int(self._threads_slider.get())

        self._clear_results()
        self._total_ports = end_port - start_port + 1
        self._stop_event.clear()

        self._scan_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        proto = "IPv6" if is_v6 else "IPv4"
        self._set_status(
            f"Scanning {ip} [{proto}]  ports {start_port}-{end_port}  {threads} threads",
            ACCENT)

        self._scan_start = time.time()
        self._scan_thread = threading.Thread(
            target=self._run_scan,
            args=(ip, start_port, end_port, timeout, threads, family),
            daemon=True)
        self._scan_thread.start()

    def _run_scan(self, host, start, end, timeout, max_threads, family):
        try:
            with ThreadPoolExecutor(max_workers=max_threads) as pool:
                futures = {pool.submit(scan_port, host, p, timeout, family): p
                           for p in range(start, end + 1)}
                for fut in futures:
                    if self._stop_event.is_set():
                        pool.shutdown(wait=False, cancel_futures=True)
                        break
                    try:
                        self._result_queue.put(fut.result())
                    except BaseException:
                        pass  # CancelledError from stop, etc.
        except Exception:
            pass
        finally:
            self._result_queue.put(None)  # sentinel always sent, even on crash

    def _stop_scan(self):
        self._stop_event.set()
        self._set_status("Stopping...", TEXT_DIM)

    # ── result polling ─────────────────────────────────────────────────────────

    def _poll_results(self):
        # Cap items processed per 50ms tick — prevents flooding Tkinter
        # when 500 threads + 0.1s timeout dump results faster than the UI can paint.
        MAX_PER_TICK = 300
        done = False
        processed = 0

        for _ in range(MAX_PER_TICK):
            try:
                item = self._result_queue.get_nowait()
            except queue.Empty:
                break
            processed += 1
            if item is None:
                done = True
                break
            port, open_, service = item
            self._scanned += 1
            if open_:
                self._open_count += 1
                self._add_result_row(port, open_, service)

        # One Tkinter update per tick regardless of how many results arrived
        if processed:
            elapsed = time.time() - getattr(self, "_scan_start", time.time())
            self._progress.set(self._scanned / max(self._total_ports, 1))
            self._stat_open.configure(text=str(self._open_count))
            self._stat_closed.configure(text=str(self._scanned - self._open_count))
            self._stat_total.configure(text=str(self._scanned))
            self._stat_time.configure(text=f"{elapsed:.1f}s")

        if done:
            elapsed = time.time() - getattr(self, "_scan_start", time.time())
            self._scan_btn.configure(state="normal")
            self._stop_btn.configure(state="disabled")
            stopped = self._stop_event.is_set()
            self._set_status(
                f"{'Stopped' if stopped else 'Done'} — "
                f"{self._open_count} open port(s) in {elapsed:.1f}s",
                ACCENT if not stopped else TEXT_DIM)
            self._stat_time.configure(text=f"{elapsed:.1f}s")
            self._progress.set(1.0)

        self.after(50, self._poll_results)


# ── entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = PortScannerApp()
    app.mainloop()
