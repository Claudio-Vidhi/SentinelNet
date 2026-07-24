import os
import unittest
from collectors.mac_collector import expand_iface
from collectors import mac_history


class TestInterfaceNormAndEuvdSort(unittest.TestCase):
    def test_expand_iface_normalizes_all_ethernet_abbreviations(self):
        self.assertEqual(expand_iface("Eth0/0"), "Ethernet0/0")
        self.assertEqual(expand_iface("Et0/0"), "Ethernet0/0")
        self.assertEqual(expand_iface("eth0/0"), "Ethernet0/0")
        self.assertEqual(expand_iface("et0/0"), "Ethernet0/0")
        self.assertEqual(expand_iface("Ethernet0/0"), "Ethernet0/0")
        self.assertEqual(expand_iface("Gi1/0/1"), "GigabitEthernet1/0/1")
        self.assertEqual(expand_iface("gi1/0/1"), "GigabitEthernet1/0/1")
        self.assertEqual(expand_iface("Fa0/1"), "FastEthernet0/1")
        self.assertEqual(expand_iface("fa0/1"), "FastEthernet0/1")
        self.assertEqual(expand_iface("Te1/0/1"), "TenGigabitEthernet1/0/1")
        self.assertEqual(expand_iface("Po1"), "Port-channel1")

    def test_mac_history_record_sightings_consolidates_eth_and_ethernet(self):
        mac_history.init_db()
        switch_ip = "192.168.1.250"
        with mac_history._connect() as c:
            c.execute("DELETE FROM mac_sightings WHERE mac=? AND switch_ip=?", ("14:33:5c:13:9f:a4", switch_ip))

        rows_eth = [{"mac": "14:33:5c:13:9f:a4", "vlan": "10", "interface": "Eth0/0"}]
        rows_ethernet = [{"mac": "14:33:5c:13:9f:a4", "vlan": "10", "interface": "Ethernet0/0"}]

        mac_history.record_sightings(rows_eth, switch_ip)
        mac_history.record_sightings(rows_ethernet, switch_ip)

        with mac_history._connect() as c:
            records = c.execute(
                "SELECT * FROM mac_sightings WHERE mac=? AND switch_ip=?",
                ("14:33:5c:13:9f:a4", switch_ip)
            ).fetchall()

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["interface"], "Ethernet0/0")
        self.assertEqual(records[0]["seen_count"], 2)

    def test_euvd_date_sorting_and_parsing_contract(self):
        js_path = os.path.join(os.path.dirname(__file__), "..", "static", "js", "threat-intel.js")
        with open(js_path, "r", encoding="utf-8") as f:
            threat_intel_js = f.read()

        core_path = os.path.join(os.path.dirname(__file__), "..", "static", "js", "core.js")
        with open(core_path, "r", encoding="utf-8") as f:
            core_js = f.read()

        # Verify date field resolution includes extended publication date keys
        self.assertIn("publicationDate", threat_intel_js)
        self.assertIn("date_published", threat_intel_js)
        self.assertIn("published_at", threat_intel_js)

        # Verify vwParseTimestamp handles seconds to ms conversion and yMd pattern
        self.assertIn("dateStr < 1e11 ? dateStr * 1000 : dateStr", threat_intel_js)
        self.assertIn("const yMd = s.match(/^(\\d{4})[/-](\\d{1,2})[/-](\\d{1,2})/", threat_intel_js)

        # Verify numeric comparison in core.js sortTableByColumn
        self.assertIn("!isNaN(numX) && !isNaN(numY)", core_js)
        self.assertIn("asc ? numX - numY : numY - numX", core_js)


if __name__ == "__main__":
    unittest.main()
