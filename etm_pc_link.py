#!/usr/bin/env python3
"""
EVE Tiles Mobile — PC Link
Receives fits "thrown" from the EVE Tiles Mobile web app on your phone and puts them on
your Windows clipboard, ready to paste into Pyfa or EVE's fitting window (Import from clipboard).

  • Standard library only — no pip installs. Run:  python etm_pc_link.py   (or double-click)
  • Shows a pairing code. Enter it on your phone: Fits tab → 🖥 PC link.
  • Intel: with "Send EVE local / d-scan to my phone" on, copying the local member list or a d-scan in EVE
    sends it to the phone's 📡 Intel tab. Only text that looks like local or a d-scan is sent, and by default
    only when an EVE window is in front.
  • Optional password: set one here (Password… button) and any device can link by typing the
    password instead of the code — this helper keeps the code posted, locked with the password.
  • Messages travel through the free ntfy.sh relay, compressed and encrypted with keys derived
    from the pairing code (PBKDF2-SHA256 → HMAC-SHA256 counter-mode stream + HMAC tag).
    The relay only ever sees the random channel name and unreadable bytes.

Optional: build a stand-alone .exe on your PC with
  pip install pyinstaller  &&  pyinstaller --onefile --noconsole --name "ETM PC Link" etm_pc_link.py
"""
import base64, hashlib, hmac, json, os, queue, secrets, struct, sys, threading, time, zlib
import urllib.request, urllib.error
from pathlib import Path

APP = 'EVE Tiles Mobile PC Link'
VERSION = '1.4'
RELAY = os.environ.get('ETM_RELAY', 'https://ntfy.sh').rstrip('/')
SALT, ITER = b'etm-pclink-v1', 150000
ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'  # no 0/O, 1/I/L
CONFIG_DIR = Path(os.environ.get('ETM_CONFIG_DIR') or (Path(os.environ.get('APPDATA', Path.home())) / 'EVE Tiles Mobile'))
CONFIG = CONFIG_DIR / 'pclink.json'

# ── crypto (must match PCL in index.html) ─────────────────────────────────────────────
def norm(code):
    return ''.join(ch for ch in (code or '').upper() if ch.isalnum())

def new_code():
    c = ''.join(secrets.choice(ALPHABET) for _ in range(10))
    return f'{c[:4]}-{c[4:8]}-{c[8:]}'

def derive(code):
    dk = hashlib.pbkdf2_hmac('sha256', norm(code).encode(), SALT, ITER, dklen=80)
    return 'etm-' + dk[:16].hex(), dk[16:48], dk[48:80]

# Password link: the pairing code is posted on a channel named from the password and locked with keys
# made from it, so another device that knows the password can fetch the code. ntfy.sh keeps messages
# about 12 hours, so the helper re-posts every few hours while it runs.
PW_SALT, PW_ITER, PW_REPOST = b'etm-pclink-pw-v1', 300000, 6 * 3600
PW_MIN = 8

def derive_pw(password):
    dk = hashlib.pbkdf2_hmac('sha256', (password or '').strip().encode('utf-8'), PW_SALT, PW_ITER, dklen=80)
    return 'etm-p-' + dk[:16].hex(), dk[16:48], dk[48:80]

def relay_post(topic, body):
    req = urllib.request.Request(f'{RELAY}/{topic}', data=body.encode(), method='POST', headers={'User-Agent': f'etm-pc-link/{VERSION}'})
    with urllib.request.urlopen(req, timeout=20) as r:
        r.read()

def publish_code(cfg):
    """Posts the current pairing code, locked with the password keys. No-op when no password is set."""
    pw = cfg.get('pw')
    if not pw:
        return False
    body = encrypt(json.dumps({'k': 'code', 'code': cfg['code'], 'ts': int(time.time() * 1000)}), bytes.fromhex(pw['enc']), bytes.fromhex(pw['mac']))
    relay_post(pw['topic'], body)
    cfg['pw']['posted'] = int(time.time()); save_config(cfg)
    return True

def set_password(cfg, password):
    password = (password or '').strip()
    if len(password) < PW_MIN:
        raise ValueError(f'Use at least {PW_MIN} characters (a short phrase is best).')
    topic, enc, mac = derive_pw(password)
    cfg['pw'] = {'topic': topic, 'enc': enc.hex(), 'mac': mac.hex()}  # keys only — the password itself is not stored
    save_config(cfg)
    return publish_code(cfg)

def clear_password(cfg):
    pw = cfg.pop('pw', None); save_config(cfg)
    if pw:  # tell devices that look it up that the password was removed
        try:
            relay_post(pw['topic'], encrypt(json.dumps({'k': 'revoked', 'ts': int(time.time() * 1000)}), bytes.fromhex(pw['enc']), bytes.fromhex(pw['mac'])))
        except Exception:
            pass

def keep_code_posted(cfg, on_status, stop):
    """Background thread: re-posts the locked code so the relay always has a fresh copy."""
    def loop():
        while not stop.is_set():
            if cfg.get('pw') and time.time() - cfg['pw'].get('posted', 0) > PW_REPOST - 60:
                try:
                    publish_code(cfg)
                except Exception as e:
                    on_status('warn', f'Could not post the password link ({e}) — will retry')
                    stop.wait(300); continue
            stop.wait(60)
    t = threading.Thread(target=loop, daemon=True); t.start(); return t

# ── Intel: PC → phone channel (separate from the phone → PC channel) ─────────────────
import re as _re
NAME_RX = _re.compile(r"^[A-Za-z0-9][A-Za-z0-9 '.\-]{1,36}$")
CHUNK = 3800

def intel_topic(code):
    _, enc, mac = derive(code)
    return 'etm-i-' + hmac.new(mac, b'intel', hashlib.sha256).digest()[:16].hex()

def classify_intel(text):
    """'local' (pilot names, one per line), 'dscan' (tab-separated scan lines) or None (anything else is never sent)."""
    lines = [l.strip() for l in (text or '').replace('\r', '').split('\n') if l.strip()]
    if not lines or len(text) > 60000:
        return None
    if sum('\t' in l for l in lines) >= max(1, len(lines) * 0.8):
        return 'dscan'
    if len(lines) <= 300 and all(NAME_RX.match(l) for l in lines) and not any(l.lower().startswith(('http', 'www.')) for l in lines):
        return 'local'
    return None

def post_chunked(topic, payload):
    if len(payload) <= CHUNK:
        relay_post(topic, payload); return
    sid = secrets.token_hex(4); n = (len(payload) + CHUNK - 1) // CHUNK
    for i in range(n):
        relay_post(topic, f'ETMC:{sid}:{i}:{n}:{payload[i * CHUNK:(i + 1) * CHUNK]}')

def send_intel(code, text):
    _, enc, mac = derive(code)
    post_chunked(intel_topic(code), encrypt(json.dumps({'k': 'intel', 'text': text, 'ts': int(time.time() * 1000)}), enc, mac))

def eve_in_front():
    """True when the foreground window is an EVE client (window class triuiScreen)."""
    if sys.platform != 'win32':
        return True
    import ctypes
    u32 = ctypes.windll.user32
    h = u32.GetForegroundWindow()
    buf = ctypes.create_unicode_buffer(256)
    u32.GetClassNameW(h, buf, 256)
    cls = buf.value
    u32.GetWindowTextW(h, buf, 256)
    return cls == 'triuiScreen' or buf.value.startswith('EVE')

def get_clipboard_text():
    if sys.platform != 'win32':
        return None
    import ctypes
    from ctypes import wintypes
    u32, k32 = ctypes.windll.user32, ctypes.windll.kernel32
    u32.GetClipboardData.restype = wintypes.HANDLE
    k32.GlobalLock.argtypes = [wintypes.HGLOBAL]; k32.GlobalLock.restype = wintypes.LPVOID
    k32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    for _ in range(10):
        if u32.OpenClipboard(None):
            break
        time.sleep(0.03)
    else:
        return None
    try:
        h = u32.GetClipboardData(13)  # CF_UNICODETEXT
        if not h:
            return None
        p = k32.GlobalLock(h)
        try:
            return ctypes.wstring_at(p)
        finally:
            k32.GlobalUnlock(h)
    finally:
        u32.CloseClipboard()

class ClipWatch(threading.Thread):
    """Watches Windows' clipboard change counter (no keyboard hook) and sends EVE local / d-scan copies."""
    def __init__(self, cfg, on_status):
        super().__init__(daemon=True)
        self.cfg, self.on_status, self.stop = cfg, on_status, threading.Event()
        self.own = 0  # our own clipboard writes (received fits) are skipped
    def run(self):
        if sys.platform != 'win32':
            return
        import ctypes
        seq = ctypes.windll.user32.GetClipboardSequenceNumber
        last = seq()
        while not self.stop.is_set():
            self.stop.wait(0.25)
            n = seq()
            if n == last:
                continue
            last = n
            if self.own and n <= self.own + 2:
                continue
            if not self.cfg.get('intel') or (self.cfg.get('intel_eve_only', True) and not eve_in_front()):
                continue
            text = get_clipboard_text()
            kind = classify_intel(text)
            if not kind:
                continue
            try:
                send_intel(self.cfg['code'], text)
                cnt = len([l for l in text.splitlines() if l.strip()])
                self.on_status('connected', f'📡 Sent {"d-scan" if kind == "dscan" else "local"} ({cnt} line{"s" if cnt != 1 else ""}) to your phone')
            except Exception as e:
                self.on_status('warn', f'Could not send intel ({e})')

def _stream(key, nonce, data):
    out = bytearray(len(data))
    for off in range(0, len(data), 32):
        ks = hmac.new(key, nonce + struct.pack('>I', off // 32), hashlib.sha256).digest()
        for i in range(min(32, len(data) - off)):
            out[off + i] = data[off + i] ^ ks[i]
    return bytes(out)

def encrypt(text, enc, mac):
    data = zlib.compress(text.encode('utf-8'), 9)[2:-4]  # raw deflate
    nonce = secrets.token_bytes(16)
    ct = _stream(enc, nonce, data)
    tag = hmac.new(mac, b'v1' + nonce + ct, hashlib.sha256).digest()[:16]
    return 'ETM1:' + base64.b64encode(nonce + ct + tag).decode()

def decrypt(payload, enc, mac):
    if not payload.startswith('ETM1:'):
        raise ValueError('not an EVE Tiles Mobile message')
    raw = base64.b64decode(payload[5:])
    nonce, ct, tag = raw[:16], raw[16:-16], raw[-16:]
    if not hmac.compare_digest(tag, hmac.new(mac, b'v1' + nonce + ct, hashlib.sha256).digest()[:16]):
        raise ValueError('wrong pairing code or damaged message')
    return zlib.decompress(_stream(enc, nonce, ct), -15).decode('utf-8')

# ── config ────────────────────────────────────────────────────────────────────────────
def load_config():
    try:
        return json.loads(CONFIG.read_text(encoding='utf-8'))
    except Exception:
        return {}

def save_config(cfg):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG.with_suffix('.tmp')
    tmp.write_text(json.dumps(cfg, indent=1), encoding='utf-8')
    tmp.replace(CONFIG)

# ── relay listener ────────────────────────────────────────────────────────────────────
class Listener(threading.Thread):
    """Streams the private ntfy channel; calls on_message(dict, msg_id) for each decrypted message."""
    def __init__(self, code, on_message, on_status, since=None):
        super().__init__(daemon=True)
        self.topic, self.enc, self.mac = derive(code)
        self.on_message, self.on_status, self.since = on_message, on_status, since
        # First run: also pick up anything sent in the last 10 minutes (e.g. the phone's test while we were connecting)
        self.first_since = str(int(time.time()) - 600)
        self.stop = threading.Event()
        self.chunks = {}  # sid -> {n, parts}

    def assemble(self, body):
        """Returns a complete ETM1 payload, or None while chunks of a bigger message are still arriving."""
        if body.startswith('ETM1:'):
            return body
        if not body.startswith('ETMC:'):
            return body
        _, sid, i, n, part = body.split(':', 4)
        g = self.chunks.setdefault(sid, {'n': int(n), 'parts': {}})
        g['parts'][int(i)] = part
        if len(g['parts']) == g['n']:
            del self.chunks[sid]
            return ''.join(g['parts'][k] for k in range(g['n']))
        return None

    def self_test(self):
        """Posts an encrypted test to our own channel; if it comes back, the PC side works end to end."""
        body = encrypt(json.dumps({'k': 'selftest', 'title': 'PC self-test', 'text': '', 'ts': int(time.time() * 1000)}), self.enc, self.mac)
        req = urllib.request.Request(f'{RELAY}/{self.topic}', data=body.encode(), method='POST', headers={'User-Agent': f'etm-pc-link/{VERSION}'})
        with urllib.request.urlopen(req, timeout=20) as r:
            r.read()

    def _fetch(self, url, timeout=30):
        req = urllib.request.Request(url, headers={'User-Agent': f'etm-pc-link/{VERSION}'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode('utf-8')

    def run(self):
        backoff = 2
        while not self.stop.is_set():
            url = f'{RELAY}/{self.topic}/json?since={self.since or self.first_since}'
            try:
                req = urllib.request.Request(url, headers={'User-Agent': f'etm-pc-link/{VERSION}'})
                with urllib.request.urlopen(req, timeout=120) as r:
                    self.on_status('connected', 'Waiting for fits from your phone')
                    backoff = 2
                    for line in r:
                        if self.stop.is_set():
                            return
                        line = line.strip()
                        if not line:
                            continue
                        ev = json.loads(line)
                        if ev.get('event') != 'message':
                            continue
                        self.since = ev.get('id') or self.since
                        body = ev.get('message', '')
                        att = ev.get('attachment') or {}
                        if att.get('url') and not body.startswith(('ETM1:', 'ETMC:')):
                            body = self._fetch(att['url'])  # long messages arrive as an attachment
                        body = self.assemble(body.strip())
                        if body is None:
                            continue
                        try:
                            self.on_message(json.loads(decrypt(body.strip(), self.enc, self.mac)), self.since)
                        except Exception as e:
                            self.on_status('warn', f'Ignored a message that could not be read ({e})')
            except Exception as e:
                if self.stop.is_set():
                    return
                why = str(getattr(e, 'reason', '') or e)[:140]
                self.on_status('offline', f'Can\'t reach {RELAY} — retrying in {backoff}s. ({e.__class__.__name__}: {why})')
                self.stop.wait(backoff)
                backoff = min(60, backoff * 2)

# ── Windows clipboard (persists after the app closes) ─────────────────────────────────
def set_clipboard(text, tk_root=None):
    if sys.platform == 'win32':
        import ctypes
        from ctypes import wintypes
        u32, k32 = ctypes.windll.user32, ctypes.windll.kernel32
        k32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]; k32.GlobalAlloc.restype = wintypes.HGLOBAL
        k32.GlobalLock.argtypes = [wintypes.HGLOBAL]; k32.GlobalLock.restype = wintypes.LPVOID
        k32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        u32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]; u32.SetClipboardData.restype = wintypes.HANDLE
        u32.OpenClipboard.argtypes = [wintypes.HWND]
        data = (text.replace('\r\n', '\n').replace('\n', '\r\n') + '\0').encode('utf-16-le')
        for _ in range(10):
            if u32.OpenClipboard(None):
                break
            time.sleep(0.05)
        else:
            raise OSError('clipboard is busy')
        try:
            u32.EmptyClipboard()
            h = k32.GlobalAlloc(0x0002, len(data))  # GMEM_MOVEABLE
            p = k32.GlobalLock(h)
            ctypes.memmove(p, data, len(data))
            k32.GlobalUnlock(h)
            u32.SetClipboardData(13, h)  # CF_UNICODETEXT
        finally:
            u32.CloseClipboard()
    elif tk_root is not None:
        tk_root.clipboard_clear(); tk_root.clipboard_append(text); tk_root.update()

def startup_file():
    return Path(os.environ.get('APPDATA', Path.home())) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup' / f'{APP}.cmd'

def set_startup(on):
    f = startup_file()
    if not on:
        f.unlink(missing_ok=True); return
    if getattr(sys, 'frozen', False):
        cmd = f'@start "" "{sys.executable}"\r\n'
    else:
        exe = Path(sys.executable)
        pyw = exe.with_name('pythonw.exe')
        cmd = f'@start "" "{pyw if pyw.exists() else exe}" "{Path(__file__).resolve()}"\r\n'
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(cmd, encoding='utf-8')

# ── GUI ───────────────────────────────────────────────────────────────────────────────
def run_gui():
    import tkinter as tk
    from tkinter import messagebox
    BG, PANEL, FG, DIM, TEAL, GOLD, RED = '#0a0e14', '#131c2a', '#c8d8e8', '#6a7888', '#40c8c8', '#c8a84b', '#d04040'
    cfg = load_config()
    if not cfg.get('code'):
        cfg['code'] = new_code(); save_config(cfg)
    q = queue.Queue()
    root = tk.Tk()
    root.title(f'{APP} {VERSION}'); root.configure(bg=BG); root.geometry('560x510'); root.minsize(460, 440)
    try:
        root.iconbitmap(default='')
    except Exception:
        pass
    font = ('Segoe UI', 10)
    tk.Label(root, text='⚡ EVE TILES MOBILE — PC LINK', bg=BG, fg=GOLD, font=('Segoe UI', 11, 'bold')).pack(pady=(14, 2))
    tk.Label(root, text='On your phone: Fits tab → 🖥 PC link → enter this code', bg=BG, fg=DIM, font=font).pack()
    code_var = tk.StringVar(value=cfg['code'])
    tk.Label(root, textvariable=code_var, bg=PANEL, fg=TEAL, font=('Consolas', 26, 'bold'), padx=18, pady=8).pack(pady=8)
    btns = tk.Frame(root, bg=BG); btns.pack()
    status_var = tk.StringVar(value='Connecting…')
    status = tk.Label(root, textvariable=status_var, bg=BG, fg=DIM, font=font, wraplength=400)
    hdr = tk.Frame(root, bg=BG); hdr.pack(fill='x', padx=16, pady=(10, 2))
    tk.Label(hdr, text='Received (double-click to copy again):', bg=BG, fg=DIM, font=font, anchor='w').pack(side='left')
    lst = tk.Listbox(root, bg=PANEL, fg=FG, selectbackground='#14324a', highlightthickness=0, borderwidth=0, font=font, height=7)
    lst.pack(fill='both', expand=True, padx=16)
    status.pack(pady=6)
    opts = tk.Frame(root, bg=BG); opts.pack(pady=(0, 10))
    start_var = tk.BooleanVar(value=startup_file().exists())
    sound_var = tk.BooleanVar(value=cfg.get('sound', True))
    history = []
    state = {'listener': None}

    def toast(title, body, color=TEAL):
        t = tk.Toplevel(root); t.overrideredirect(True); t.attributes('-topmost', True); t.configure(bg=color)
        inner = tk.Frame(t, bg=PANEL); inner.pack(padx=2, pady=2)
        tk.Label(inner, text=title, bg=PANEL, fg=color, font=('Segoe UI', 11, 'bold'), padx=14, pady=(8)).pack(anchor='w')
        tk.Label(inner, text=body, bg=PANEL, fg=FG, font=font, padx=14, justify='left').pack(anchor='w', pady=(0, 10))
        t.update_idletasks()
        w, h = t.winfo_width(), t.winfo_height()
        t.geometry(f'+{t.winfo_screenwidth() - w - 24}+{t.winfo_screenheight() - h - 70}')
        t.after(4500, t.destroy)
        if sound_var.get() and sys.platform == 'win32':
            try:
                import winsound; winsound.MessageBeep(winsound.MB_OK)
            except Exception:
                pass

    def start_listener():
        if state['listener']:
            state['listener'].stop.set()
        l = Listener(cfg['code'], lambda m, i: q.put(('msg', m, i)), lambda k, s: q.put(('status', k, s)), since=cfg.get('since'))
        state['listener'] = l; l.start()

    def poll():
        try:
            while True:
                kind, a, b = q.get_nowait()
                if kind == 'status':
                    status_var.set({'connected': '🟢 ', 'offline': '🟠 ', 'warn': '⚠ '}.get(a, '') + b)
                    status.configure(fg=TEAL if a == 'connected' else (RED if a == 'warn' else DIM))
                else:
                    m, mid = a, b
                    cfg['since'] = mid; save_config(cfg)
                    if m.get('k') == 'test':
                        toast('✓ Phone linked', 'Test received — fits you throw will land on the clipboard.')
                        status_var.set('🟢 Phone linked — waiting for fits'); continue
                    if m.get('k') == 'selftest':
                        toast('✓ PC side works', 'This PC can send and receive through the relay.')
                        status_var.set('🟢 Connection test passed — waiting for fits'); continue
                    text = m.get('text', '')
                    try:
                        if sys.platform == 'win32':
                            import ctypes; watch.own = ctypes.windll.user32.GetClipboardSequenceNumber()
                        set_clipboard(text, root)
                    except Exception as e:
                        toast('⚠ Clipboard busy', str(e), RED); continue
                    title = m.get('title') or 'Fit'
                    history.insert(0, (title, text)); del history[20:]
                    lst.delete(0, 'end')
                    for t_, _ in history:
                        lst.insert('end', '  ' + t_)
                    toast(f'📋 {title}', 'Copied — Ctrl+V into Pyfa, or EVE fitting window → Import from clipboard')
        except queue.Empty:
            pass
        root.after(200, poll)

    def self_test():
        status_var.set('Testing connection…')
        def go():
            try:
                state['listener'].self_test()
            except Exception as e:
                q.put(('status', 'warn', f'Test failed: could not send to {RELAY} ({e})'))
        threading.Thread(target=go, daemon=True).start()

    def clear_list():
        history.clear(); lst.delete(0, 'end'); status_var.set('List cleared.')

    def copy_code():
        root.clipboard_clear(); root.clipboard_append(cfg['code']); status_var.set('Code copied.')

    def regen():
        if not messagebox.askyesno(APP, 'Make a new code? Your phone will need to be linked again' + (' (or link it again with your password).' if cfg.get('pw') else '.')):
            return
        cfg['code'] = new_code(); cfg.pop('since', None); save_config(cfg); code_var.set(cfg['code']); start_listener()
        if cfg.get('pw'):
            threading.Thread(target=lambda: publish_code(cfg), daemon=True).start()

    def pw_label():
        pw_var.set('🔑 Password set — other devices can link with it' if cfg.get('pw') else 'No password — devices link with the code above')

    def password():
        from tkinter import simpledialog
        if cfg.get('pw'):
            ans = messagebox.askyesnocancel(APP, 'A password is set.\n\nYes = change it\nNo = remove it (devices then need the code)\nCancel = keep it')
            if ans is None:
                return
            if ans is False:
                threading.Thread(target=lambda: clear_password(cfg), daemon=True).start(); pw_label(); status_var.set('Password removed.'); return
        p1 = simpledialog.askstring(APP, f'Password for linking other devices (at least {PW_MIN} characters — a short phrase is best):', show='•', parent=root)
        if p1 is None:
            return
        p2 = simpledialog.askstring(APP, 'Type it again:', show='•', parent=root)
        if p2 is None:
            return
        if p1.strip() != p2.strip():
            messagebox.showerror(APP, "The two passwords don't match."); return
        status_var.set('Setting password…')
        def go():
            try:
                set_password(cfg, p1)
                q.put(('status', 'connected', 'Password set. On another device: 🖥 PC link → "Link with my PC password".'))
            except ValueError as e:
                cfg.pop('pw', None); save_config(cfg); q.put(('status', 'warn', str(e)))
            except Exception as e:
                q.put(('status', 'warn', f'Password saved, but posting it failed ({e}) — it will retry while this window is open'))
            root.after(0, pw_label)
        threading.Thread(target=go, daemon=True).start()

    def again(_e=None):
        sel = lst.curselection()
        if sel:
            set_clipboard(history[sel[0]][1], root); status_var.set(f'Copied again: {history[sel[0]][0]}')

    def toggle_start():
        try:
            set_startup(start_var.get())
        except Exception as e:
            messagebox.showerror(APP, f'Could not change startup: {e}'); start_var.set(startup_file().exists())

    def toggle_sound():
        cfg['sound'] = sound_var.get(); save_config(cfg)

    mk = lambda parent, text, cmd: tk.Button(parent, text=text, command=cmd, bg=PANEL, fg=FG, activebackground='#14324a', activeforeground=TEAL, relief='flat', padx=10, pady=3, font=font)
    mk(btns, 'Copy code', copy_code).pack(side='left', padx=4)
    mk(btns, 'Test connection', self_test).pack(side='left', padx=4)
    mk(btns, 'New code', regen).pack(side='left', padx=4)
    mk(btns, 'Password…', password).pack(side='left', padx=4)
    pw_var = tk.StringVar(); pw_label()
    tk.Label(root, textvariable=pw_var, bg=BG, fg=DIM, font=('Segoe UI', 9)).pack(before=hdr, pady=(6, 0))
    keep_code_posted(cfg, lambda k, s_: q.put(('status', k, s_)), threading.Event())
    lst.bind('<Double-Button-1>', again)
    mk(hdr, 'Clear', clear_list).pack(side='right')
    for text, var, cmd in (('Start with Windows', start_var, toggle_start), ('Sound', sound_var, toggle_sound)):
        tk.Checkbutton(opts, text=text, variable=var, command=cmd, bg=BG, fg=FG, selectcolor=PANEL, activebackground=BG, activeforeground=TEAL, font=font).pack(side='left', padx=8)
    intel_var = tk.BooleanVar(value=cfg.get('intel', False)); eveonly_var = tk.BooleanVar(value=cfg.get('intel_eve_only', True))
    def toggle_intel():
        cfg['intel'] = intel_var.get(); cfg['intel_eve_only'] = eveonly_var.get(); save_config(cfg)
        status_var.set('📡 Copy local or a d-scan in EVE — it goes to your phone\'s Intel tab.' if cfg['intel'] else 'Intel sending off.')
    iopts = tk.Frame(root, bg=BG); iopts.pack(pady=(0, 10))
    tk.Checkbutton(iopts, text='📡 Send EVE local / d-scan copies to my phone', variable=intel_var, command=toggle_intel, bg=BG, fg=FG, selectcolor=PANEL, activebackground=BG, activeforeground=TEAL, font=font).pack(side='left', padx=6)
    tk.Checkbutton(iopts, text='only when EVE is in front', variable=eveonly_var, command=toggle_intel, bg=BG, fg=DIM, selectcolor=PANEL, activebackground=BG, activeforeground=TEAL, font=('Segoe UI', 9)).pack(side='left')
    watch = ClipWatch(cfg, lambda k, s_: q.put(('status', k, s_))); watch.start()
    start_listener()
    root.after(200, poll)
    root.mainloop()

# ── command line ──────────────────────────────────────────────────────────────────────
def main(argv):
    if '--selftest' in argv:
        code = new_code(); _, enc, mac = derive(code)
        msg = json.dumps({'k': 'fit', 'title': 'Test', 'text': '[Rifter, Test]\nDamage Control II\n'})
        assert json.loads(decrypt(encrypt(msg, enc, mac), enc, mac))['text'].startswith('[Rifter')
        assert classify_intel('Dom Test\nSome Pilot\nX-ray 9') == 'local'
        assert classify_intel('1234\tRifter\tRifter\t5 km\n555\tTitan\tAvatar\t9 AU') == 'dscan'
        assert classify_intel('https://example.com') is None and classify_intel('def f(x):\n  return {x}') is None
        print('self-test OK'); return 0
    if '--decrypt' in argv:  # --decrypt CODE PAYLOAD  (debug helper)
        i = argv.index('--decrypt'); _, enc, mac = derive(argv[i + 1]); print(decrypt(argv[i + 2], enc, mac)); return 0
    if '--send-intel' in argv:  # --send-intel FILE : send a saved local list / d-scan (what the clipboard watch does)
        cfg = load_config()
        text = Path(argv[argv.index('--send-intel') + 1]).read_text(encoding='utf-8')
        kind = classify_intel(text)
        if not kind:
            print('not local or d-scan — not sent'); return 2
        send_intel(cfg['code'], text); print(f'sent {kind}'); return 0
    if '--set-password' in argv or '--clear-password' in argv:  # --set-password "my phrase" / --clear-password
        cfg = load_config()
        if not cfg.get('code'):
            cfg['code'] = new_code(); save_config(cfg)
        if '--clear-password' in argv:
            clear_password(cfg); print('password removed'); return 0
        try:
            set_password(cfg, argv[argv.index('--set-password') + 1])
        except ValueError as e:
            print(e); return 2
        print('password set'); return 0
    if '--headless' in argv:  # console mode: prints received fits and copies them
        cfg = load_config()
        if not cfg.get('code'):
            cfg['code'] = new_code(); save_config(cfg)
        print(f'{APP} {VERSION} — pairing code: {cfg["code"]}', flush=True)
        keep_code_posted(cfg, lambda k, s: print(f'STATUS {k}: {s}', flush=True), threading.Event())
        def on_msg(m, mid):
            cfg['since'] = mid; save_config(cfg)
            print(f'MESSAGE {json.dumps(m)}', flush=True)
            if m.get('k') not in ('test', 'selftest') and sys.platform == 'win32':
                set_clipboard(m.get('text', ''))
        l = Listener(cfg['code'], on_msg, lambda k, s: print(f'STATUS {k}: {s}', flush=True), since=cfg.get('since'))
        l.start()
        try:
            while l.is_alive():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        return 0
    run_gui()
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
