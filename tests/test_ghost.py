"""Maze Ghost tests. No root, no Ghost account needed.

The firewall is tested for real: its rules are loaded into a throwaway network
namespace (an unprivileged user namespace, where our uid is 0) once with the
"ghost" uid being ours and once with it being someone else's, and
tests/fw_probe.py reports what got through.
"""
from __future__ import annotations

import os
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SYSTEM = ROOT / "system"

from mazeghost import status  # noqa: E402


def _netns_ok() -> bool:
    if not (shutil.which("unshare") and shutil.which("nft") and shutil.which("ip")):
        return False
    r = subprocess.run(["unshare", "--user", "--map-root-user", "--net", "true"],
                       capture_output=True)
    return r.returncode == 0


@unittest.skipUnless(_netns_ok(), "unprivileged network namespaces or nft/ip missing")
class FirewallTestCase(unittest.TestCase):
    def probe(self, ghost_uid: int) -> str:
        script = (
            "ip link set lo up; ip link add d0 type dummy; ip link set d0 up; "
            "ip addr add 10.255.255.1/32 dev d0; ip route add default dev d0; "
            f"{SYSTEM}/ghost-firewall load {ghost_uid} && "
            # A second load is the upgrade path: it must replace, not add.
            f"{SYSTEM}/ghost-firewall load {ghost_uid} && "
            f"python3 {ROOT}/tests/fw_probe.py")
        r = subprocess.run(["unshare", "--user", "--map-root-user", "--net", "bash", "-c", script],
                           capture_output=True, text=True, timeout=60)
        return r.stdout + r.stderr

    def test_ghost_reaches_only_tor(self):
        out = self.probe(0)
        self.assertIn("tcp 93.184.216.34:443 -> connected", out)       # …to the TransPort
        self.assertIn("tor saw: ['93.184.216.34:443']", out, "Tor got the real destination")
        self.assertIn("udp dns 9.9.9.9:53    -> answered", out)        # …by the DNSPort
        self.assertNotIn("udp 9.9.9.9:443       -> answered", out)
        self.assertNotIn("tcp 127.0.0.1:631     -> connected", out, "local services are closed")
        self.assertNotIn("tcp6 ::1:631          -> connected", out)

    def test_other_accounts_are_untouched(self):
        out = self.probe(4242)
        self.assertIn("tcp 127.0.0.1:631     -> connected", out)
        self.assertIn("tor saw: [] dns queries: 0", out, "nothing of theirs is redirected")

    @unittest.skipUnless(shutil.which("wg"), "wireguard-tools missing")
    def test_packets_without_an_owner_are_untouched(self):
        """Kernel WireGuard sends its encapsulated packets from a socket no uid
        owns, so "meta skuid" never matches them. They must not be caught by
        the Ghost chains, or nobody's kernel WireGuard works."""
        script = (
            "ip link set lo up; "
            f"{SYSTEM}/ghost-firewall load 1001 && "
            "python3 -c '\n"
            "import socket\n"
            "u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "u.bind((\"127.0.0.1\", 51999)); u.settimeout(4)\n"
            "try: print(\"wg handshake bytes:\", len(u.recvfrom(2048)[0]))\n"
            "except OSError: print(\"wg handshake bytes: 0\")\n"
            "' & sleep 0.3; "
            "ip link add wg0 type wireguard && "
            "wg set wg0 private-key <(wg genkey) peer $(wg genkey | wg pubkey) "
            "endpoint 127.0.0.1:51999 allowed-ips 10.9.0.2/32 && "
            "ip addr add 10.9.0.1/24 dev wg0 && ip link set wg0 up && "
            "{ ping -c1 -W1 10.9.0.2 >/dev/null 2>&1; wait; }")
        r = subprocess.run(["unshare", "--user", "--map-root-user", "--net", "bash", "-c", script],
                           capture_output=True, text=True, timeout=60)
        out = r.stdout + r.stderr
        if "wg handshake bytes:" not in out:
            self.skipTest(f"no kernel WireGuard in a network namespace: {out.strip()}")
        self.assertIn("wg handshake bytes: 148", out)

    def test_rules_parse(self):
        r = subprocess.run([str(SYSTEM / "ghost-firewall"), "render", "1001"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("meta skuid 1001 jump ghost_filter", r.stdout)
        self.assertIn("meta skuid 1001 jump ghost_nat", r.stdout)
        # "!= uid accept" lets packets with no owner fall through to the drop.
        self.assertNotIn("meta skuid !=", r.stdout)


class SessionScriptTestCase(unittest.TestCase):
    """The session scripts run as root in a drop-in for the Ghost account's
    user manager. Whatever else they do, for any other uid they must do
    nothing and succeed — a mistake there would lock people out."""

    def test_syntax(self):
        for name in ("ghost-firewall", "ghost-session-start", "ghost-session-stop",
                     "ghost-login-screen"):
            r = subprocess.run(["bash", "-n", str(SYSTEM / name)], capture_output=True)
            self.assertEqual(r.returncode, 0, name)
        r = subprocess.run(["bash", "-n", str(ROOT / "packaging" / "maze-ghost.install")],
                           capture_output=True)
        self.assertEqual(r.returncode, 0)

    def test_other_uids_are_left_alone(self):
        ghost = subprocess.run(["id", "-u", "ghost"], capture_output=True, text=True)
        other = "4242424" if ghost.returncode else str(int(ghost.stdout) + 1)
        for name in ("ghost-session-start", "ghost-session-stop"):
            r = subprocess.run([str(SYSTEM / name), other], capture_output=True, text=True,
                               timeout=20)
            self.assertEqual(r.returncode, 0, f"{name}: {r.stderr}")
            self.assertEqual(r.stdout + r.stderr, "", f"{name} did something for uid {other}")

    def test_start_refuses_without_the_firewall_before_touching_anything(self):
        """The order inside the script: the firewall check comes before the
        first mount, so a refused login has changed nothing."""
        text = (SYSTEM / "ghost-session-start").read_text()
        self.assertLess(text.index("nft list table inet maze_ghost"), text.index("mount -t tmpfs"))

    def test_firewall_stop_ends_the_session_first(self):
        text = (SYSTEM / "ghost-firewall").read_text()
        stop = text[text.index("    stop)"):]
        self.assertLess(stop.index("terminate-user ghost"), stop.index("delete table"))


def _userns_with_ghost_ok() -> bool:
    """A user namespace where we are root AND a second uid (1000, "ghost")
    exists: needs newuidmap/newgidmap and a subuid range for this user."""
    if not (shutil.which("unshare") and shutil.which("setpriv") and shutil.which("nft")):
        return False
    r = subprocess.run(["unshare", "--user", "--map-root-user", "--map-auto", "--mount", "--net",
                        "setpriv", "--reuid=1000", "--regid=1000", "--clear-groups", "true"],
                       capture_output=True)
    return r.returncode == 0


# Runs ghost-session-start for real — mount, nft, install, setpriv — as root of
# a throwaway user+mount+network namespace in which uid 1000 is "ghost". /home
# and /var/lib are fresh tmpfs mounts there, /etc/passwd is our own, and
# systemctl is a stub, so nothing on the host is read or changed.
#   $1 script to run   $2 scenario: clean | link | persist-link | existing
_SESSION_HARNESS = r"""
set -eu
script="$1" scenario="$2"
T="$(mktemp -d)"
mkdir -p "$T/bin" "$T/skel"
printf '#!/bin/sh\nexit 0\n' > "$T/bin/systemctl"; chmod 755 "$T/bin/systemctl"
printf 'root:x:0:0::/root:/bin/bash\nghost:x:1000:1000::/home/ghost:/bin/bash\n' > "$T/passwd"
printf 'root:x:0:\nghost:x:1000:\n' > "$T/group"
echo hello > "$T/skel/.welcome"
mount --bind "$T/passwd" /etc/passwd
mount --bind "$T/group" /etc/group
mount -t tmpfs -o mode=0755 none /home
mount -t tmpfs -o mode=0755 none /var/lib
install -d -m 0700 /home/ghost
install -d -m 0755 /var/lib/maze-ghost
install -d -m 0755 /var/lib/victim          # root's, must stay root's
as_ghost() { setpriv --reuid=1000 --regid=1000 --clear-groups "$@"; }
case "$scenario" in
    link)           # an earlier Ghost session left a link where the capsule dir goes
        install -d -o 1000 -g 1000 -m 0700 /var/lib/maze-ghost/persistent
        as_ghost ln -s /var/lib/victim /var/lib/maze-ghost/persistent/maze-capsule ;;
    persist-link)   # the persistent dir itself is a link (only root could do this)
        ln -s /var/lib/victim /var/lib/maze-ghost/persistent ;;
    existing)       # a capsule from an earlier session is there and must survive
        install -d -o 1000 -g 1000 -m 0700 /var/lib/maze-ghost/persistent
        as_ghost install -d -m 0700 /var/lib/maze-ghost/persistent/maze-capsule
        as_ghost sh -c 'echo kept > /var/lib/maze-ghost/persistent/maze-capsule/c' ;;
esac
ip link set lo up
"$FIREWALL" load 1000
sed -e "s#/usr/share/maze-ghost/skel#$T/skel#" \
    -e "s#/usr/lib/maze-ghost/ghost-login-screen#true#" "$script" > "$T/start"
chmod 755 "$T/start"
set +e
PATH="$T/bin:$PATH" "$T/start" 1000 2> "$T/err"
echo "exit=$?"
set -e
sed 's/^/stderr: /' "$T/err"
echo "victim=$(stat -c '%u:%g %a' /var/lib/victim)"
echo "persist=$(stat -c '%F %u:%g %a' /var/lib/maze-ghost/persistent 2>&1)"
echo "capsule=$(stat -c '%F %u:%g %a' /var/lib/maze-ghost/persistent/maze-capsule 2>&1)"
echo "homelink=$(readlink /home/ghost/.local/share/maze-capsule 2>&1 || echo none)"
echo "home=$(stat -c '%u:%g %a' /home/ghost) welcome=$(stat -c '%u' /home/ghost/.welcome)"
echo "kept=$(cat /var/lib/maze-ghost/persistent/maze-capsule/c 2>/dev/null || echo none)"
"""


@unittest.skipUnless(_userns_with_ghost_ok(),
                     "no user namespace with a second uid (newuidmap + /etc/subuid needed)")
class SessionStartPersistenceTestCase(unittest.TestCase):
    """GH1: root must never create/chown/chmod a path inside the Ghost
    account's persistent directory. `install -d` follows a symlink, so a link
    left there by a Ghost session handed its target (e.g. /etc/sudoers.d) to
    the Ghost account at the next login — a way from Ghost to root."""

    def run_start(self, scenario: str, script: Path | None = None) -> dict[str, str]:
        r = subprocess.run(
            ["unshare", "--user", "--map-root-user", "--map-auto", "--mount", "--net",
             "bash", "-c", _SESSION_HARNESS, "harness",
             str(script or SYSTEM / "ghost-session-start"), scenario],
            capture_output=True, text=True, timeout=60,
            env=dict(os.environ, FIREWALL=str(SYSTEM / "ghost-firewall")))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out: dict[str, str] = {"stderr": ""}
        for line in r.stdout.splitlines():
            key, _, value = line.partition("=") if not line.startswith("stderr: ") \
                else ("stderr", "", line[8:])
            out[key] = out.get(key, "") + value if key == "stderr" else value
        return out

    def test_clean_first_login(self):
        out = self.run_start("clean")
        self.assertEqual(out["exit"], "0", out)
        self.assertEqual(out["persist"], "directory 1000:1000 700")
        self.assertEqual(out["capsule"], "directory 1000:1000 700")
        self.assertEqual(out["homelink"], "/var/lib/maze-ghost/persistent/maze-capsule")
        self.assertEqual(out["home"], "1000:1000 700 welcome=1000")
        self.assertEqual(out["victim"], "0:0 755")

    def test_capsules_from_earlier_sessions_are_kept(self):
        out = self.run_start("existing")
        self.assertEqual(out["exit"], "0", out)
        self.assertEqual(out["kept"], "kept")
        self.assertEqual(out["capsule"], "directory 1000:1000 700")
        self.assertEqual(out["homelink"], "/var/lib/maze-ghost/persistent/maze-capsule")

    def test_planted_link_does_not_hand_its_target_to_ghost(self):
        out = self.run_start("link")
        self.assertEqual(out["victim"], "0:0 755", "root followed Ghost's link: " + str(out))
        # The login still works — just without kept capsules this time.
        self.assertEqual(out["exit"], "0", out)
        self.assertIn("capsules will not be kept", out["stderr"])
        self.assertTrue(out["homelink"].startswith("readlink:") or out["homelink"].endswith("none"),
                        out["homelink"])
        self.assertEqual(out["home"], "1000:1000 700 welcome=1000")

    def test_persistent_dir_that_is_a_link_is_left_alone(self):
        out = self.run_start("persist-link")
        self.assertEqual(out["victim"], "0:0 755", out)
        self.assertEqual(out["exit"], "0", out)
        self.assertIn("is not a directory", out["stderr"])

    def test_no_root_install_inside_the_persistent_dir(self):
        """Static guard against the bug coming back: the only things run on a
        path under $persist/ are done through setpriv as the Ghost account."""
        text = (SYSTEM / "ghost-session-start").read_text()
        code = [l for l in text.splitlines() if not l.lstrip().startswith("#")]
        for line in code:
            if '"$persist/' in line and "ln -sfn" not in line:
                self.assertIn("install -d -m 0700", line, line)
                # ...and that install is the setpriv'd one (continuation line).
                self.assertIn("setpriv", code[code.index(line) - 1], line)


class ConfigTestCase(unittest.TestCase):
    def test_torrc_is_valid(self):
        if not shutil.which("tor"):
            self.skipTest("tor missing")
        import tempfile
        base = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
        d = Path(tempfile.mkdtemp(prefix="gt-", dir=base))
        try:
            (d / "data").mkdir(mode=0o700)
            (d / "inc").mkdir()
            text = (SYSTEM / "torrc").read_text()
            text = (text.replace("/var/lib/maze-ghost-tor", str(d / "data"))
                        .replace("/etc/maze-ghost/torrc.d/", str(d / "inc") + "/")
                        .replace("Log notice syslog", "Log notice stderr")
                        .replace("9140", "29140").replace("9153", "29153").replace("9150", "29150"))
            (d / "torrc").write_text(text)
            r = subprocess.run(["tor", "--verify-config", "-f", str(d / "torrc")],
                               capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stdout[-400:])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_ports_agree(self):
        fw = (SYSTEM / "ghost-firewall").read_text()
        torrc = (SYSTEM / "torrc").read_text()
        self.assertIn("TRANS_PORT=9140", fw)
        self.assertIn("TransPort 127.0.0.1:9140", torrc)
        self.assertIn("DNS_PORT=9153", fw)
        self.assertIn("DNSPort 127.0.0.1:9153", torrc)

    def test_polkit_rule(self):
        if not shutil.which("node"):
            self.skipTest("node missing")
        js = """
        const fs=require('fs'); let rule;
        global.polkit={Result:{NO:'no',NOT_HANDLED:'nh'},addRule:f=>rule=f};
        eval(fs.readFileSync(process.argv[1],'utf8'));
        const t=(u,a)=>rule({id:a},{user:u});
        const ids=JSON.parse(process.argv[2]);
        console.log(JSON.stringify(ids.map(([u,a])=>t(u,a))));
        """
        cases = {
            ("ghost", "org.freedesktop.login1.hibernate"): "no",
            ("ghost", "org.freedesktop.login1.suspend"): "nh",
            ("someone", "org.freedesktop.login1.hibernate"): "nh",
            # GH2: a cellular line past Tor, a hotspot, machine identifiers,
            # and changes that outlive the session.
            ("ghost", "org.freedesktop.ModemManager1.Messaging"): "no",
            ("ghost", "org.freedesktop.ModemManager1.Location"): "no",
            ("ghost", "org.freedesktop.ModemManager1.Voice"): "no",
            ("ghost", "org.freedesktop.NetworkManager.wifi.share.open"): "no",
            ("ghost", "org.freedesktop.NetworkManager.settings.modify.system"): "no",
            ("ghost", "org.freedesktop.NetworkManager.settings.modify.global-dns"): "no",
            ("ghost", "org.freedesktop.hostname1.get-hardware-serial"): "no",
            ("ghost", "org.freedesktop.hostname1.set-hostname"): "no",
            ("ghost", "org.freedesktop.timedate1.set-timezone"): "no",
            ("ghost", "org.opensuse.cupspkhelper.mechanism.printer-add"): "no",
            # GH5: lingering would keep the session (and its home) past logout.
            ("ghost", "org.freedesktop.login1.set-self-linger"): "no",
            ("someone", "org.freedesktop.login1.set-self-linger"): "nh",
            # What a Ghost session still needs: its own Wi-Fi, suspend.
            ("ghost", "org.freedesktop.NetworkManager.settings.modify.own"): "nh",
            ("ghost", "org.freedesktop.NetworkManager.network-control"): "nh",
            ("ghost", "org.freedesktop.NetworkManager.wifi.scan"): "nh",
            ("someone", "org.freedesktop.ModemManager1.Messaging"): "nh",
        }
        r = subprocess.run(["node", "-e", js, str(SYSTEM / "49-maze-ghost.rules"),
                            json.dumps([list(k) for k in cases])],
                           capture_output=True, text=True)
        self.assertEqual(dict(zip(cases, json.loads(r.stdout))), cases, r.stderr)


class LeakTestCase(unittest.TestCase):
    """Ways out that do not go through the firewall: system services that
    would make the connection as their own user."""

    def test_no_way_to_resolved(self):
        """Names looked up through systemd-resolved would leave outside Tor."""
        text = (ROOT / "packaging" / "maze-ghost.install").read_text()
        self.assertIn("InaccessiblePaths=-/run/systemd/resolve/io.systemd.Resolve", text)

    def test_nothing_scheduled_outlives_the_session(self):
        """GH5: cron, at and linger are cleared at the end of every session,
        and linger also at its start."""
        stop = (SYSTEM / "ghost-session-stop").read_text()
        for step in ("crontab -u ghost -r", "atrm", "loginctl disable-linger ghost",
                     "/var/lib/systemd/linger/ghost"):
            self.assertIn(step, stop)
        start = (SYSTEM / "ghost-session-start").read_text()
        self.assertIn("loginctl disable-linger ghost", start)

    def test_socks_port_isolates_per_credentials(self):
        """GH6: Tor Browser's per-site circuits rely on IsolateSOCKSAuth."""
        torrc = (SYSTEM / "torrc").read_text()
        socks = next(l for l in torrc.splitlines() if l.startswith("SocksPort"))
        self.assertIn("IsolateSOCKSAuth", socks)
        self.assertNotIn("NoIsolateSOCKSAuth", torrc)

    def test_local_sockets_that_go_out_are_hidden(self):
        """GH3: the firewall sees packets, not UNIX sockets. A Ghost program
        could print through CUPS, resolve over Avahi, or steer the owner's
        Mullvad (its socket is world-writable) as those services' users."""
        text = (ROOT / "packaging" / "maze-ghost.install").read_text()
        dropin = text[text.index("cat > \"$dropin\""):text.index("\nEOF\n")]
        for path in ("/run/avahi-daemon/socket", "/run/cups/cups.sock", "/run/docker.sock",
                     "/run/podman", "/run/libvirt", "/run/mullvad-vpn", "/run/tor",
                     "/run/entropy-shield"):
            self.assertIn(f"InaccessiblePaths=-{path}\n", dropin + "\n", path)
        # Ghost's own Tor must not live under anything hidden.
        torrc = (SYSTEM / "torrc").read_text()
        self.assertNotIn("/run/tor", torrc)

    @unittest.skipUnless(shutil.which("systemd-run"), "no systemd")
    def test_hidden_socket_cannot_be_reached(self):
        """The same setting, applied for real to a throwaway user unit."""
        import socket as _s
        import tempfile
        d = tempfile.mkdtemp(dir=os.environ.get("XDG_RUNTIME_DIR") or None)
        path = os.path.join(d, "svc.sock")
        srv = _s.socket(_s.AF_UNIX)
        srv.bind(path)
        srv.listen()
        os.chmod(path, 0o666)
        probe = ("import socket,sys\ns=socket.socket(socket.AF_UNIX)\n"
                 "try:\n s.connect(sys.argv[1]); print('REACHED')\n"
                 "except OSError as e: print('refused')\n")
        try:
            r = subprocess.run(["systemd-run", "--user", "--wait", "--pipe", "--quiet",
                                "-p", f"InaccessiblePaths=-{path}",
                                "python3", "-c", probe, path],
                               capture_output=True, text=True, timeout=60)
        finally:
            srv.close()
            shutil.rmtree(d, ignore_errors=True)
        if "Failed to" in r.stderr:
            self.skipTest(r.stderr.strip()[:200])
        self.assertEqual(r.stdout.strip(), "refused", r.stderr)

    def test_home_is_mounted_outside_user_managers_namespace(self):
        """user@ hides resolved, so it has a mount namespace of its own: a home
        mounted by an ExecStartPre= there is seen by no one (1.0.1: every
        Ghost login went straight back to the login screen)."""
        text = (ROOT / "packaging" / "maze-ghost.install").read_text()
        dropin = text[text.index("cat > \"$dropin\""):text.index("\nEOF\n")]
        settings = "\n".join(l for l in dropin.splitlines() if not l.startswith("#"))
        self.assertNotIn("ExecStartPre", settings)
        self.assertNotIn("ExecStopPost", settings)
        self.assertIn("Requires=maze-ghost-session@%i.service", dropin)
        self.assertIn("After=maze-ghost-session@%i.service", dropin)
        unit = (SYSTEM / "maze-ghost-session@.service").read_text()
        for line in ("BindsTo=user@%i.service", "Before=user@%i.service",
                     "ExecStart=/usr/lib/maze-ghost/ghost-session-start %i",
                     "ExecStop=/usr/lib/maze-ghost/ghost-session-stop %i",
                     "RemainAfterExit=yes"):
            self.assertIn(line, unit)
        for sandboxing in ("Private", "Protect", "Inaccessible", "ReadOnly", "TemporaryFileSystem"):
            self.assertNotIn(sandboxing, unit.split("[Service]")[1])

    def test_dbus_policy(self):
        import xml.etree.ElementTree as ET
        root = ET.parse(SYSTEM / "maze-ghost-dbus.conf").getroot()
        policy = root.find("policy")
        self.assertEqual(policy.get("user"), "ghost")
        denied = {d.get("send_destination") for d in policy.findall("deny")}
        for name in ("org.freedesktop.resolve1", "org.freedesktop.GeoClue2",
                     "org.freedesktop.PackageKit", "org.freedesktop.Avahi",
                     "org.freedesktop.ModemManager1", "org.freedesktop.timesync1",
                     "org.bluez", "fi.w1.wpa_supplicant1"):
            self.assertIn(name, denied)
        # Ghost may still join a Wi-Fi of its own; polkit limits the rest.
        self.assertNotIn("org.freedesktop.NetworkManager", denied)
        self.assertIsNone(policy.find("allow"))

    def test_upgrade_never_ends_a_session(self):
        """Restarting the firewall service would end a running Ghost session."""
        text = (ROOT / "packaging" / "maze-ghost.install").read_text()
        upgrade = text[text.index("post_upgrade()"):text.index("pre_remove()")]
        self.assertNotIn("restart maze-ghost-firewall", upgrade)
        self.assertIn("ghost-firewall start", upgrade)

    def test_wifi_files_of_ghost_only(self):
        """At boot NetworkManager is not running yet: the saved files go."""
        import re
        import tempfile
        text = (SYSTEM / "ghost-session-stop").read_text()
        pattern = re.search(r"grep -qE '([^']+)'", text).group(1)
        with tempfile.TemporaryDirectory() as d:
            cases = {"ghost.nmconnection": "permissions=user:ghost;\n",
                     "both.nmconnection": "permissions=user:berk;user:ghost;\n",
                     "ghostly.nmconnection": "permissions=user:ghostly;\n",
                     "shared.nmconnection": "permissions=\n"}
            for name, body in cases.items():
                Path(d, name).write_text("[connection]\n" + body)
            hit = {name for name in cases
                   if subprocess.run(["grep", "-qE", pattern, str(Path(d, name))]).returncode == 0}
        self.assertEqual(hit, {"ghost.nmconnection", "both.nmconnection"})


    def _forget_ghost(self, state: str, passwd: str) -> str:
        """Run ghost-login-screen on files of our own."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            Path(d, "state.conf").write_text(state)
            Path(d, "passwd").write_text(passwd)
            r = subprocess.run([str(SYSTEM / "ghost-login-screen"), f"{d}/state.conf", f"{d}/passwd"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            return Path(d, "state.conf").read_text()

    def test_login_screen_is_handed_back_at_login_and_at_logout(self):
        for name in ("ghost-session-start", "ghost-session-stop"):
            self.assertIn("/usr/lib/maze-ghost/ghost-login-screen", (SYSTEM / name).read_text(), name)
        self.assertIn("system/ghost-login-screen", (ROOT / "packaging" / "PKGBUILD").read_text())

    def test_login_screen_without_a_state_file(self):
        r = subprocess.run([str(SYSTEM / "ghost-login-screen"), "/nonexistent/state.conf", "/etc/passwd"],
                           capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stdout + r.stderr), (0, ""))

    PASSWD = ("root:x:0:0::/root:/bin/bash\n"
              "ghost:x:1000:1000::/home/ghost:/usr/bin/zsh\n"
              "berk:x:1001:1001::/home/berk:/usr/bin/zsh\n"
              "guest:x:1002:1002::/home/guest:/bin/bash\n"
              "svc:x:999:999::/:/usr/bin/nologin\n")

    def test_login_screen_forgets_ghost(self):
        state = "[Last]\nSession=/usr/share/wayland-sessions/plasma.desktop\nUser=ghost\n"
        self.assertEqual(self._forget_ghost(state, self.PASSWD),
                         "[Last]\nSession=/usr/share/wayland-sessions/plasma.desktop\nUser=berk\n")

    def test_login_screen_keeps_another_user(self):
        state = "[Last]\nUser=guest\n"
        self.assertEqual(self._forget_ghost(state, self.PASSWD), state)

    def test_login_screen_without_another_user(self):
        passwd = "ghost:x:1000:1000::/home/ghost:/usr/bin/zsh\nnobody:x:65534:65534::/:/usr/bin/nologin\n"
        self.assertEqual(self._forget_ghost("[Last]\nUser=ghost\n", passwd), "[Last]\n")


class StatusTestCase(unittest.TestCase):
    def test_disk_swap_ignores_zram(self):
        text = ("Filename Type Size Used Priority\n"
                "/dev/zram0 partition 1 0 100\n/swap/swapfile file 1 0 -1\n")
        self.assertEqual(status.disk_swap(text), ["/swap/swapfile"])
        self.assertEqual(status.disk_swap("Filename Type\n/dev/zram0 partition\n"), [])

    def test_tor_check(self):
        import io

        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        self.assertEqual(status.tor_check(opener=lambda *a, **k: Resp(b'{"IsTor":true,"IP":"1.2.3.4"}')),
                         (True, "1.2.3.4"))

        def boom(*a, **k):
            raise OSError("no network")
        self.assertEqual(status.tor_check(opener=boom), (False, ""))

    def test_i18n(self):
        import re
        from mazeghost.gui import i18n
        en, tr = i18n.STRINGS["en"], i18n.STRINGS["tr"]
        self.assertEqual(set(en), set(tr))
        for k in en:
            self.assertEqual(set(re.findall(r"{(\w+)}", en[k])), set(re.findall(r"{(\w+)}", tr[k])), k)


if __name__ == "__main__":
    unittest.main(verbosity=2)
