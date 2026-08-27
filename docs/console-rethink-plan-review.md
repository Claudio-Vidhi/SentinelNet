# Console Rethink Plan — Review Findings

> Review of `docs/console-rethink-plan.md` and its commits on `feat/console-rethink`.
> Reviewed 2026-08-26 against branch HEAD `0911372`.
> Verdict: **high quality**. Claims were checked against the tree at the plan's own
> commit and against HEAD; line references are almost all exact, the root-cause
> analysis reproduces in code, and the sequencing logic holds. Findings below are
> a handful of small inaccuracies, two stale sections, and one test-coverage gap.

## 1. Commits reviewed

| Commit | Subject | Diff |
| :--- | :--- | :--- |
| `520eaed` | docs(ux): console rethink implementation plan | +356 (initial plan) |
| `ee59b15` | docs(ux): item 9 is a correctness removal, not a tidy-up | +32/−8 |
| `d6dfab6` | docs(ux): record ARP stale-binding root cause behind item 9 | +78/−15 |
| `4879f41` | docs(ux): decide the recency rule, add the time-range filter as item 11 | +84/−7 |

All four are documentation-only; commit messages match their diffs and each
message states what changed and why. The plan narrates a real investigation
arc: assumption -> open question -> reproduced root cause -> decided rule.

## 2. Claims verified TRUE (checked at `4879f41`, the last plan commit)

| Plan claim | Evidence |
| :--- | :--- |
| `routers/deps.py:91` is `user_group_scope`; `:104` raised `"Site '{group}' is not allowed for your profile."` | exact at `520eaed` (confirmed via `git show`); the Site/Group mismatch was real |
| `observability/ingesters/ipfix.py:82` carries `exporter_ip` on every flow record | exact |
| `routers/commands.py:293` `_ssh_failure_hint()`, `:327` `/api/ws-terminal/{ip}` | exact (decorator :326, def :327) |
| `collectors/mac_history.py:373` upsert key is `(mac, ip, source_ip)` | exact |
| `endpoint_inventory()` ARP query did **not** `SELECT last_seen` | true then: `SELECT mac, ip, tenant` only |
| `templates/dashboard.html:1265` `data-loc-view="clientmap"` pill | exact |
| `ai/mcp_server.py:148` client-map MCP tool | registration spans :147–156 |
| 23 top-level surfaces | exact: 23 `nav-item` buttons incl. `tab-fortigate`, `tab-wlc`, `tab-redundancy` |
| Nav grouped by verbs Indaga/Inventario/Valuta/Modifica/Amministra | true (`dashboard.html:268–321` then and now) |
| `services/site_manager.py` sites: central/agent/jump, `sites.json` + `agent_jobs.db` | true (`site_manager.py:4–13, 33–34`) |
| `static/js/i18n.js` has `it` and `en` blocks | true (`en` at :1857) |
| `core.js` hardcodes `showToast('Errore di caricamento modulo', 'error')` | true (`core.js:994`, still present at HEAD) |
| `_inventory_stamp()` versions the data, not the question | true (`mac_history.py:706`) |
| Root-cause mechanics: append-only `arp_entries`, lexicographic `sorted()` puts the stale IP first, `MULTI-IP` polluted, `client_type` inheritable from a stale IP | all reproduce in the code as written |
| Branch cut from `Dev` on 2026-08-26 | merge-base `3ca0678` = tip of `Dev`, same date |

## 3. Errors and inaccuracies found in the plan

### 3.1 Factual (minor)

1. **"11 separate tenant selectors" is the stale headline number.** The plan
   quotes `ui_tab_overlap_analysis.md`'s header, but that document's own
   addendum (its lines 12–13) corrects the count to **10** after A3 shipped
   (2026-08-11). A strict count of tenant `<select>` elements at the plan
   commit is ~8 (identTenant, haTenantFilter, locTenant, wlcTenantSelect,
   genCfgTenant, ptTenantSelect, driftTenantSelect, aiAttachTenant); the
   higher counts come from including group/site scope selectors. The argument
   stands either way, but the number as quoted was already superseded by its
   own source.
2. **`ips = sorted({...})` line reference is off by one** — plan says
   `mac_history.py:800`, the statement was at :801 at `4879f41`.
3. **`client_type` lookup reference is off by two** — plan says
   `mac_history.py:826`; :826 is the comment, the `assigned = next(...)`
   expression is at :828. Substance of the claim is correct.
4. **"~870 lines" for `client-map.js`** — it was 806 at the plan commit;
   it is 870 only at HEAD (after `2e13142`). Harmless, but the figure was
   not accurate when written.
5. **Versioning section says "Items 1–10"** — the plan has 11 items; item 11
   is a feature too, so the range should be 1–11.

### 3.2 Stale (the branch moved past the document)

6. **Header "Status: plan only — no code changed on this branch"** is now
   false. Five code commits followed: `d61010a` (recency + time-range fix),
   `0d99635` (group error strings), `2e13142` (topbar, palette, verdicts,
   endpoint unification), `82ac580` (SSH step streaming), `0911372`
   (version 0.21.0).
7. **"Open: sequencing" list (item 9) was never updated after the decision.**
   Step 1 "Decide the recency window (product call)" is already decided in the
   same document (the rule at "The fix: newest scan wins, per source"), and
   steps 2–4 are all implemented at HEAD (`d61010a` fixed both read paths,
   `2e13142` removed the Client Map pill). The list still reads as future
   work. The related `tenant` overwrite (step 3) was only partially
   mitigated: `d61010a` added `new_tenant = tenant if tenant else
   existing["tenant"]` (`mac_history.py:376`), so an empty tenant no longer
   clobbers, but a scan from a *different* tenant still overwrites the field —
   the plan's own "needs its own verification" note is still open.

### 3.3 Test-coverage gap versus the plan's own requirement

8. Item 9 demands four regression scenarios: IP change, dual-stack, two
   gateways, and *"a MAC whose only binding is older than the newest scan of a
   different MAC (must not be wrongly excluded)"*. `tests/test_endpoint_inventory.py`
   covers the first three (`test_ip_cambiato_scarta_ip_vecchio`,
   `test_dual_stack_conserva_entrambi`, `test_due_gateway_conservano_uno_ciascuno`)
   plus time-range and one-row-per-client. **The fourth scenario has no named
   test.** Risk is low — the filter keys on `(mac, tenant, source_ip)` within
   one MAC's rows, so cross-MAC exclusion cannot happen by construction — but
   the plan explicitly required the guard and it is not pinned by a test.

## 4. Implementation status at HEAD (plan vs branch)

| Item | Status | Evidence |
| :--- | :--- | :--- |
| 1. Global tenant selector | mostly done | `globalTenantSelect` + `globalTenantChanged` (`core.js:1344–1366`); **no URL reflection found** — the acceptance criterion "reflected in the URL" has no implementation (URLSearchParams in `core.js` only serve auth tokens) |
| 2. Device context chip | done | `globalDeviceChip` (`core.js:1378–1390`) |
| 3. Situazione verdicts | done | `verdictReachability/Backup/Cve/Drift` (`home.js:197–318`); Home promoted above the groups, renamed |
| 4. Command palette | done | `core.js:1398+` |
| 5. FortiGate/WLC/HA demoted | done | nav 23 -> 20 items; the three tabs gone from the sidebar |
| 6. Rename + error string | done | "Gestione Tenant", "Sedi", `deps.py:104` now says Group (`0d99635`) |
| 7. Three layout intents | not started (L, deferred by design) | — |
| 8. Streaming SSH + skeletons | partial | step streaming done (`82ac580`); the hardcoded Italian toast (`core.js:994`) is still not routed through i18n |
| 9. Retire Client Map (after fix) | done, in the plan's own order | read paths fixed first (`d61010a`), pill removed after (`2e13142`); `client-map.js` kept for shared logic (MAC Tracker / pane switching), `/api/arp/client-map` route and MCP tool retained |
| 10. Preview tag | done | caution-coloured `preview-badge` on Diagnosi Client (`dashboard.html:1486`) |
| 11. Time-range filter | done | `frm`/`to` on `endpoint_inventory()`, `client_map()`, `search_arp()`; in the MCP tool schemas (`mcp_server.py:140–162`); `frm`,`to` in the cache key (`mac_history.py:770`); `outside_retention` + `retention_days` in the response (`mac_history.py:924–932`) |
| Versioning | done | 0.20.0 -> 0.21.0 (`0911372`), MINOR as the plan prescribed, `core/version.py` and `pyproject.toml` in sync |

## 5. Observations outside the document

- `ai/mcp_server.py:150` illustrates the client_map tool with `10.0.0.5`.
  AGENTS.md mandates RFC 5737 example addresses (`192.0.2.x` /
  `198.51.100.x`) in tracked files; this example should be normalised.
- The recency rule itself (`mac_history.py:851–862` and :603–612) matches
  the decided wording exactly, including the per-`source_ip` grouping and the
  "range set -> history mode" escape hatch. The implementation honoured the
  plan.

## 6. Quality assessment

- **Structure**: diagnosis -> target model -> sequenced items -> traps ->
  verification. Each item has scope, touches, and acceptance criteria. Strong.
- **Honesty**: four corrected assumptions are marked `[corrected]` instead of
  being silently dropped; item 9 was re-opened against its own premise when
  evidence contradicted it. This is the document's best trait.
- **Traceability**: nearly every claim carries a `file:line`, and nearly
  every one checked out. The three off-by-one/two references above are the
  only misses in ~20 spot checks.
- **Weaknesses**: the document is not maintained after implementation started
  (status header, sequencing list), quotes one stale number from its companion
  analysis, and one of its own mandatory regression scenarios has no test.

Recommendation: update the status header and the item-9 sequencing list to
reflect `d61010a`/`2e13142`, add the missing cross-MAC regression test,
and close out item 1's URL-reflection criterion (implement it or strike it).
