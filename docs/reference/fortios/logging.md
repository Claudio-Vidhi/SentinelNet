# FortiOS 7.4.12 — Logging Implementation Notes (extracted)

## CLI: Querying event logs (SSH fallback)

Log queries via CLI are stateful: set filters first, then display.

```
execute log filter category event
execute log filter field subtype vpn
execute log filter field action ssl-login-fail
execute log display
```

- `execute log filter category <name>` — selects log category (e.g., `event`).
- `execute log filter field <fieldname> <value>` — narrows by log field; repeatable (each call adds a filter). Fields shown: `subtype`, `action`.
- `execute log display` — prints matching records after filters are applied.

### Log record format (key=value, space-separated)

Example record returned:

```
1: date=2019-02-15 time=10:57:56 logid="0101039426" type="event" subtype="vpn" level="alert"
vd="root" eventtime=1550257076 logdesc="SSL VPN login fail" action="ssl-login-fail"
tunneltype="ssl-web" tunnelid=0 remip=10.1.100.254 user="u1" group="g1" dst_host="N/A"
reason="sslvpn_login_password_expired" msg="SSL user failed to logged in"
```

Parsing notes:
- Records prefixed with index + colon (`1:`).
- Mixed quoted (`logid="0101039426"`) and unquoted (`tunnelid=0`, `remip=10.1.100.254`) values — parser must handle both.
- `eventtime` is epoch seconds (`1550257076`); `date`/`time` are local, split fields.
- `logid` is a 10-digit string identifying the event type (e.g., `0101039426` = SSL VPN login fail).
- `vd` = VDOM name (`root`) — filter on this in multi-VDOM deployments.
- Useful correlation fields: `type`, `subtype`, `level`, `action`, `reason`, `user`, `group`, `remip`, `tunneltype`, `tunnelid`.

## Related monitor data (SSL VPN sessions — CLI)

```
get vpn ssl monitor
```

Output has two sections:

1. `SSL-VPN Login Users:` columns — `Index User AuthType Timeout From HTTP in/out HTTPS in/out`
2. `SSL-VPN sessions:` columns — `Index User Source IP Duration I/O Bytes Tunnel/Dest IP`

Example rows:
```
0  sslvpnuser1  1(1)  291  10.1.100.254  0/0  0/0
0  sslvpnuser1  10.1.100.254  9  22099/43228  10.212.134.200
```

Gotchas:
- Counters are paired `in/out` values separated by `/` (e.g., `22099/43228`).
- `AuthType` shows as `N(N)` format, e.g., `1(1)`.
- Correlate `get vpn ssl monitor` session data with event logs via `user` and `remip`/`Source IP`.

*(No REST endpoints appear on this source page; CLI commands above are the fallback path.)*