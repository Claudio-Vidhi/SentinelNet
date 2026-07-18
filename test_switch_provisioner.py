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


def test_hardening_defaults_and_uplink_lag():
    cfg = _sample_cfg()
    cfg["uplink_pc_id"] = 2
    cfg["storm_control"] = True

    config = sp.build_config(cfg)

    # Hardening sempre attivo di default
    assert "service tcp-keepalives-in" in config
    assert "no vstack" in config
    assert "login block-for 120 attempts 5 within 60" in config
    assert "logging buffered 16384" in config
    # Errdisable recovery per le cause abilitate (bpduguard + port-security + storm)
    assert "errdisable recovery cause bpduguard" in config
    assert "errdisable recovery cause psecure-violation" in config
    assert "errdisable recovery cause storm-control" in config
    assert "errdisable recovery interval 300" in config
    # Storm-control sulle porte access
    assert "storm-control broadcast level 5.00" in config
    # Uplink EtherChannel LACP: membri + interfaccia logica
    assert "channel-group 2 mode active" in config
    assert "interface Port-channel2" in config


def test_hardening_can_be_disabled():
    cfg = _sample_cfg()
    cfg.update({"login_block": False, "no_vstack": False,
                "errdisable_recovery": False})

    config = sp.build_config(cfg)

    assert "login block-for" not in config
    assert "no vstack" not in config
    assert "errdisable recovery" not in config
    assert "channel-group" not in config      # nessun uplink_pc_id


def test_aaa_default_none_matches_local_only():
    cfg = _sample_cfg()
    config = sp.build_config(cfg)

    assert "aaa new-model" in config
    assert "aaa authentication login default local" in config
    assert "aaa authorization exec default local" in config
    assert "radius server" not in config
    assert "tacacs server" not in config
    assert "SENTINEL-AAA" not in config


def test_aaa_radius_adds_server_and_group():
    cfg = _sample_cfg()
    cfg["aaa_protocol"] = "radius"
    cfg["aaa_servers"] = [
        {"ip": "10.0.0.20", "key": "R@diusKey1", "auth_port": 1812, "acct_port": 1813},
        {"ip": "10.0.0.21", "key": "R@diusKey2"},
    ]

    config = sp.build_config(cfg)

    assert "radius server RADIUS-1" in config
    assert " address ipv4 10.0.0.20 auth-port 1812 acct-port 1813" in config
    assert " key R@diusKey1" in config
    assert "radius server RADIUS-2" in config
    assert " address ipv4 10.0.0.21 auth-port 1812 acct-port 1813" in config
    assert "aaa group server radius SENTINEL-AAA" in config
    assert " server name RADIUS-1" in config
    assert " server name RADIUS-2" in config
    assert "aaa authentication login default group SENTINEL-AAA local" in config
    assert "aaa authorization exec default group SENTINEL-AAA local" in config
    # username locale resta come fallback
    assert "username netadmin privilege 15 secret" in config


def test_aaa_tacacs_adds_server_and_group():
    cfg = _sample_cfg()
    cfg["aaa_protocol"] = "tacacs"
    cfg["aaa_servers"] = [{"ip": "10.0.0.30", "key": "TacKey1"}]

    config = sp.build_config(cfg)

    assert "tacacs server TACACS-1" in config
    assert " address ipv4 10.0.0.30" in config
    assert " key TacKey1" in config
    assert "aaa group server tacacs+ SENTINEL-AAA" in config
    assert " server name TACACS-1" in config
    assert "aaa authentication login default group SENTINEL-AAA local" in config
    assert "aaa authorization exec default group SENTINEL-AAA local" in config
    assert "username netadmin privilege 15 secret" in config


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
    test_hardening_defaults_and_uplink_lag()
    test_hardening_can_be_disabled()
    test_aaa_default_none_matches_local_only()
    test_aaa_radius_adds_server_and_group()
    test_aaa_tacacs_adds_server_and_group()
    test_distribution_role_adds_routing_and_svis()
    print("OK")
