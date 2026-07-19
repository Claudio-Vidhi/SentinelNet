# -*- coding: utf-8 -*-
"""Unit test minimale per fortigate_provisioner.build_config: verifica le
sezioni AAA (RADIUS/TACACS+) aggiunte in T3, oltre al caso di default
(nessun AAA remoto) che deve restare invariato."""

import fortigate_provisioner as fp


def _sample_cfg():
    return {
        "hostname": "FGT-TEST-01",
        "admin_user": "netadmin",
        "admin_password": "S3cret!",
        "mgmt_interface": "mgmt",
        "mgmt_ip": "10.0.0.254",
        "mgmt_mask": "255.255.255.0",
    }


def test_aaa_default_none_no_remote_admin():
    config = fp.build_config(_sample_cfg())

    assert "config user radius" not in config
    assert "config user tacacs+" not in config
    assert "SENTINEL-AAA" not in config
    assert "set remote-auth enable" not in config
    # admin locale invariato
    assert "edit netadmin" in config
    assert "set accprofile \"super_admin\"" in config


def test_aaa_radius_adds_user_and_group():
    cfg = _sample_cfg()
    cfg["aaa_protocol"] = "radius"
    cfg["aaa_server_ip"] = "10.0.0.20"
    cfg["aaa_key"] = "R@diusKey1"

    config = fp.build_config(cfg)

    assert "config user radius" in config
    assert "edit SENTINEL-RADIUS" in config
    assert "set server 10.0.0.20" in config
    assert "set secret R@diusKey1" in config
    assert "config user group" in config
    assert "edit SENTINEL-AAA" in config
    assert "set member SENTINEL-RADIUS" in config
    assert "set remote-auth enable" in config
    assert "set remote-group SENTINEL-AAA" in config
    # admin locale resta come fallback
    assert "edit netadmin" in config


def test_aaa_tacacs_adds_user_and_group():
    cfg = _sample_cfg()
    cfg["aaa_protocol"] = "tacacs"
    cfg["aaa_server_ip"] = "10.0.0.30"
    cfg["aaa_key"] = "TacKey1"

    config = fp.build_config(cfg)

    assert "config user tacacs+" in config
    assert "edit SENTINEL-TACACS" in config
    assert "set server 10.0.0.30" in config
    assert "set key TacKey1" in config
    assert "config user group" in config
    assert "set member SENTINEL-TACACS" in config
    assert "set remote-auth enable" in config
    assert "edit netadmin" in config


if __name__ == "__main__":
    test_aaa_default_none_no_remote_admin()
    test_aaa_radius_adds_user_and_group()
    test_aaa_tacacs_adds_user_and_group()
    print("OK")
