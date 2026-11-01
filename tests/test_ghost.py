"""Maze Ghost tests. No root, no Ghost account needed.

The firewall is tested for real: its rules are loaded into a throwaway network
namespace (an unprivileged user namespace, where our uid is 0) once with the
"ghost" uid being ours and once with it being someone else's, and
tests/fw_probe.py reports what got through.
"""
from __future__ import annotations

import os
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
            f"{SYSTEM}/ghost-firewall render {ghost_uid} | nft -f - && "
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

    def test_rules_parse(self):
        r = subprocess.run([str(SYSTEM / "ghost-firewall"), "render", "1001"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("meta skuid != 1001 accept", r.stdout)


class SessionScriptTestCase(unittest.TestCase):
    """The session scripts run as root in a drop-in for the Ghost account's
    user manager. Whatever else they do, for any other uid they must do
    nothing and succeed — a mistake there would lock people out."""

    def test_syntax(self):
        for name in ("ghost-firewall", "ghost-session-start", "ghost-session-stop"):
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
        console.log([t('ghost','org.freedesktop.login1.hibernate'),
                     t('ghost','org.freedesktop.login1.suspend'),
                     t('someone','org.freedesktop.login1.hibernate')].join(','));
        """
        r = subprocess.run(["node", "-e", js, str(SYSTEM / "49-maze-ghost.rules")],
                           capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "no,nh,nh")


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
