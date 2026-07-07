# -*- coding: utf-8 -*-
"""Unit test minimale per switch_provisioner.build_config: verifica che la
config generata contenga le sezioni chiave attese per un input di esempio."""

import switch_provisioner as sp


def _sample_cfg():
    return {
        "hostname": "SW-TEST-01",
        "role": "access",
        "domain": "example.local",
        "mgmt_vlan": 99,
        "mgmt_ip": "192.168.99.10",
        "mgmt_mask": "255.255.255.0",
        "mgmt_gw": "192.168.99.1",
        "admin_user": "netadmin",
        "admin_password": "Str0ngP@ss",
        "enable_secret": "EnableSecret1",
        "ssh_only": True,
        "banner": "Authorized access only",
        "ntp_servers": ["10.0.0.1", "10.0.0.2"],
        "syslog_server": "10.0.0.50",
        "snmpv3": {"user": "snmpadmin", "auth_pass": "authpass", "priv_pass": "privpass"},
        "vlans": [{"id": 10, "name": "DATA"}, {"id": 20, "name": "VOICE"}],
        "vtp_mode": "transparent",
        "stp_mode": "rapid-pvst",
        "bpduguard": True,
        "port_security": True,
        "dhcp_snooping": True,
        "dhcp_snooping_vlans": "10,20",
        "cdp_enabled": True,
        "lldp_enabled": True,
        "access_ports": ["GigabitEthernet1/0/1-24"],
        "access_vlan": 10,
        "trunk_ports": ["GigabitEthernet1/0/25-28"],
        "trunk_allowed_vlans": "10,20,99",
    }


def test_access_config_contains_expected_sections():
    config = sp.build_config(_sample_cfg())

    assert "hostname SW-TEST-01" in config
    assert "service password-encryption" in config
    assert "no ip http server" in config
    assert "ip domain-name example.local" in config
    assert "crypto key generate rsa modulus 2048" in config
    assert "ip ssh version 2" in config
    assert "transport input ssh" in config
    assert "vtp mode transparent" in config
    assert "vlan 10" in config and " name DATA" in config
    assert "interface Vlan99" in config
    assert "ip address 192.168.99.10 255.255.255.0" in config
    assert "ip default-gateway 192.168.99.1" in config
    assert "spanning-tree mode rapid-pvst" in config
    assert "spanning-tree portfast bpduguard default" in config
    assert "ip dhcp snooping" in config
    assert "switchport port-security" in config
    assert "interface range GigabitEthernet1/0/1-24" in config
    assert "switchport mode access" in config
    assert "interface range GigabitEthernet1/0/25-28" in config
    assert "switchport mode trunk" in config
    assert "switchport trunk allowed vlan 10,20,99" in config
    assert "banner motd" in config
    assert "ntp server 10.0.0.1" in config
    assert "logging host 10.0.0.50" in config
    assert "snmp-server user snmpadmin" in config
    assert "line vty 0 15" in config
    assert config.strip().endswith("end")


def test_distribution_role_adds_routing_and_svis():
    cfg = _sample_cfg()
    cfg["role"] = "distribution"
    cfg["svis"] = [{"vlan": 10, "ip": "10.1.10.1", "mask": "255.255.255.0"}]
    cfg["default_route_gw"] = "10.1.0.1"

    config = sp.build_config(cfg)

    assert "ip routing" in config
    assert "interface Vlan10" in config
    assert "ip address 10.1.10.1 255.255.255.0" in config
    assert "ip route 0.0.0.0 0.0.0.0 10.1.0.1" in config


if __name__ == "__main__":
    test_access_config_contains_expected_sections()
    test_distribution_role_adds_routing_and_svis()
    print("OK")
