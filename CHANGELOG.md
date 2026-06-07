# Changelog

All notable changes to ot-turbolaser are recorded here. The format follows
Keep a Changelog, and the project uses semantic versioning.

## [0.3.1] - 2026-06-07

Initial open-source release. ot-turbolaser fabricates a believable OT/ICS network
and replays it onto an isolated mirror so a passive sensor discovers a coherent
asset inventory: every asset fused to one MAC, IP, vendor, and name.

### Added
- **Full asset identity (MAC ↔ IP ↔ DNS).** Assets bind MAC↔IP from an
  authoritative ARP `is-at` reply, solicited by an organically-distributed
  control-cell graph (no subnet scan). Each carries a real vendor OUI and
  resolves a recognisable hostname (`LINE-01-PLC`, `CELL-02-S7`, …) via a
  per-zone DNS resolver.
- **Believable plant.** A per-zone bill of materials — controllers, a managed
  switch, an HMI, an engineering workstation, and a zone-edge firewall at `.1` —
  plus Purdue L3 operations (DCS) zones of historians, OPC/domain/application
  servers, and operator stations.
- **CVE attribution.** ~10% of assets (the real-model controllers) carry
  advisory-sourced CVEs, delivered as genuine OT protocol exchanges
  (EtherNet/IP, Modbus, S7comm, SNMP).
- **`turbolaser verify`.** A self-contained post-deploy oracle: profiles the
  emitted ARP against a reference band and scores a sensor's CSV export for
  MAC↔IP union-rate and hostname coverage against the sealed plan.
- **Operator surface.** `plan` / `fire` / `halt` / `pewpew` / `reload` /
  `zones` / `verify`, an isolated bridge with a SPAN mirror, weighted capture
  selection, inter-run gap distributions, a tx watchdog, a JSON status
  heartbeat, and systemd + Proxmox deployment.

### Notes
- No DHCP is ever synthesized: it is not an OT protocol and would be a tell.
- Replay runs only on an isolated segment with no route to a production network.
