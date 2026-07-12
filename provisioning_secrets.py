# -*- coding: utf-8 -*-
"""Gestione segreti nel provisioning day-0 (finding I-2).

Le config generate per visualizzazione/download NON devono contenere segreti
in chiaro: i valori sensibili del payload del wizard vengono sostituiti con
placeholder ``{{VAULT:<percorso>}}`` PRIMA di generare il testo. I valori
reali vengono usati ("materializzati") solo al momento del push SSH/seriale,
in memoria, senza mai essere persistiti o loggati.

La generazione di un file completamente materializzato resta possibile solo
con flag esplicito (``materialized=true``) e produce una voce di audit.
"""

# Sottostringhe di chiave che identificano un valore segreto nel payload del
# wizard (enable_secret, admin_password, snmpv3.auth_pass/priv_pass,
# ha.password, psksecret, ...).
_SECRET_KEY_HINTS = ("password", "secret", "pass", "psk")


def is_secret_key(key: str) -> bool:
    k = (key or "").lower()
    return any(h in k for h in _SECRET_KEY_HINTS)


def mask_secrets(cfg, _path=""):
    """Ritorna una copia di ``cfg`` (dict annidato) con ogni valore segreto
    sostituito dal placeholder ``{{VAULT:<percorso.chiave>}}``. I valori vuoti
    o None restano invariati (non generano righe di config)."""
    if isinstance(cfg, dict):
        out = {}
        for k, v in cfg.items():
            path = f"{_path}.{k}" if _path else k
            if isinstance(v, (dict, list)):
                out[k] = mask_secrets(v, path)
            elif is_secret_key(k) and isinstance(v, str) and v:
                out[k] = "{{VAULT:" + path + "}}"
            else:
                out[k] = v
        return out
    if isinstance(cfg, list):
        return [mask_secrets(v, _path) for v in cfg]
    return cfg
