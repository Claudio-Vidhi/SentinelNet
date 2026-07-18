"""
Unit tests for fw_analyzers.fortios.analyze (generic sections envelope).

Copre l'analizzatore firewall FortiOS che alimenta il tab Firewall del Config
Analyzer: envelope {"vendor","sections":[{id,label_key,columns,rows}]} con
policy, address/service objects, schedule, VIP, IP pool, interfacce/zone, VPN
IPsec/SSL, amministratori e autenticazione, estratti da una config FortiOS
grezza (config/edit/set/next/end). Puro e tollerante.
"""
import unittest

from fw_analyzers import fortios

SAMPLE_CONFIG = '''
#config-version=FGVM64-7.2.5-FW-build1517:opmode=0:vdom=0
config system interface
    edit "port1"
        set vdom "root"
        set ip 10.0.0.1 255.255.255.0
        set allowaccess ping https ssh
    next
    edit "port2"
        set vdom "root"
        set ip 192.168.1.1 255.255.255.0
        set allowaccess ping
    next
end
config system zone
    edit "lan"
        set interface "port2"
    next
end
config firewall policy
    edit 1
        set name "outbound"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "lan-net"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTPS"
        set nat enable
    next
    edit 2
        set name "block-telnet"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set service "TELNET"
    next
end
config firewall vip
    edit "web-vip"
        set extip 203.0.113.10
        set mappedip "10.0.0.20"
        set extintf "port1"
        set extport 443
        set mappedport 443
    next
end
config firewall ippool
    edit "nat-pool"
        set type overload
        set startip 203.0.113.100
        set endip 203.0.113.110
    next
end
config firewall address
    edit "lan-net"
        set subnet 192.168.1.0 255.255.255.0
    next
end
config firewall addrgrp
    edit "grp-srv"
        set member "lan-net"
    next
end
config firewall service custom
    edit "HTTPS-8443"
        set tcp-portrange 8443
    next
end
config firewall schedule recurring
    edit "worktime"
        set day monday tuesday
        set start 08:00
        set end 18:00
    next
end
config vpn ipsec phase1-interface
    edit "vpn-hub"
        set interface "port1"
        set remote-gw 198.51.100.1
        set psksecret ENC verysecret
    next
end
config vpn ipsec phase2-interface
    edit "vpn-hub-p2"
        set phase1name "vpn-hub"
    next
end
config vpn ssl settings
    set servercert "Fortinet_Factory"
    set tunnel-ip-pools "SSLVPN_TUNNEL_ADDR1"
    set psksecret hushhush
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set trusthost1 10.0.0.0 255.255.255.0
    next
end
config user radius
    edit "corp-radius"
        set server 10.0.0.50
    next
end
config user group
    edit "sso-group"
        set group-type fsso-service
        set member "CN=Users"
    next
end
'''


def _section(env, sid):
    return next(s for s in env["sections"] if s["id"] == sid)


def _rows(env, sid):
    return _section(env, sid)["rows"]


class TestFortiosEnvelope(unittest.TestCase):

    def setUp(self):
        self.env = fortios.analyze(SAMPLE_CONFIG)

    def test_vendor_and_section_ids(self):
        self.assertEqual(self.env["vendor"], "fortios")
        ids = [s["id"] for s in self.env["sections"]]
        self.assertEqual(ids, [
            "policies", "addresses", "address_groups", "services",
            "schedules", "vips", "ippools", "interfaces", "vpn_ipsec",
            "vpn_ssl", "administrators", "authentication",
        ])

    def test_sections_have_label_keys_and_columns(self):
        for s in self.env["sections"]:
            self.assertEqual(s["label_key"], f"fw.sec.{s['id']}")
            for c in s["columns"]:
                self.assertEqual(c["label_key"], f"fw.col.{c['key']}")

    def test_policies(self):
        rows = {r["id"]: r for r in _rows(self.env, "policies")}
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows["1"]["name"], "outbound")
        self.assertEqual(rows["1"]["srcaddr"], "lan-net")
        self.assertEqual(rows["1"]["action"], "accept")
        self.assertEqual(rows["1"]["nat"], "enable")
        self.assertEqual(rows["2"]["action"], "deny")
        self.assertEqual(rows["2"]["nat"], "disable")

    def test_addresses_and_groups(self):
        addr = {r["name"]: r for r in _rows(self.env, "addresses")}
        self.assertEqual(addr["lan-net"]["subnet"], "192.168.1.0/24")
        grp = _rows(self.env, "address_groups")
        self.assertEqual(grp[0]["members"], "lan-net")

    def test_services(self):
        svc = {r["name"]: r for r in _rows(self.env, "services")}
        self.assertEqual(svc["HTTPS-8443"]["tcp_portrange"], "8443")

    def test_schedules(self):
        sch = _rows(self.env, "schedules")[0]
        self.assertEqual(sch["name"], "worktime")
        self.assertEqual(sch["type"], "recurring")
        self.assertEqual(sch["day"], "monday, tuesday")
        self.assertEqual(sch["start"], "08:00")

    def test_vips_and_ippools(self):
        vip = _rows(self.env, "vips")[0]
        self.assertEqual(vip["extip"], "203.0.113.10")
        self.assertEqual(vip["mappedip"], "10.0.0.20")
        pool = _rows(self.env, "ippools")[0]
        self.assertEqual(pool["name"], "nat-pool")
        self.assertEqual(pool["startip"], "203.0.113.100")

    def test_interfaces_with_zone(self):
        ifs = {r["name"]: r for r in _rows(self.env, "interfaces")}
        self.assertEqual(ifs["port1"]["ip"], "10.0.0.1/24")
        self.assertEqual(ifs["port2"]["zone"], "lan")
        self.assertEqual(ifs["port1"]["allowaccess"], "ping, https, ssh")

    def test_vpn_ipsec_joins_phase2(self):
        vpn = _rows(self.env, "vpn_ipsec")[0]
        self.assertEqual(vpn["name"], "vpn-hub")
        self.assertEqual(vpn["remote_gw"], "198.51.100.1")
        self.assertEqual(vpn["phase2"], "vpn-hub-p2")

    def test_vpn_ssl_redacts_secret(self):
        ssl = {r["key"]: r["value"] for r in _rows(self.env, "vpn_ssl")}
        self.assertEqual(ssl["servercert"], "Fortinet_Factory")
        self.assertEqual(ssl["psksecret"], "***REDACTED***")

    def test_administrators(self):
        adm = _rows(self.env, "administrators")[0]
        self.assertEqual(adm["name"], "admin")
        self.assertEqual(adm["accprofile"], "super_admin")
        self.assertIn("10.0.0.0", adm["trusthost"])

    def test_authentication_flags_sso(self):
        rows = {r["name"]: r for r in _rows(self.env, "authentication")}
        self.assertEqual(rows["corp-radius"]["kind"], "radius")
        self.assertEqual(rows["corp-radius"]["server"], "10.0.0.50")
        self.assertEqual(rows["sso-group"]["kind"], "group")
        self.assertEqual(rows["sso-group"]["sso"], "yes")

    def test_tolerant_of_empty_or_garbage_input(self):
        empty = fortios.analyze("")
        self.assertEqual(empty["vendor"], "fortios")
        self.assertTrue(all(s["rows"] == [] for s in empty["sections"]))
        # non deve mai sollevare eccezioni
        fortios.analyze("not a fortios config at all\n\t***")
        fortios.analyze(None)


if __name__ == "__main__":
    unittest.main()
