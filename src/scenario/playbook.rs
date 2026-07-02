//! The phased attack playbook.
//!
//! A playbook is an ordered list of phases (recon -> initial access ->
//! manipulation -> impact). Each phase carries its ATT&CK-for-ICS technique IDs,
//! a dwell (how many announce bursts it occupies), and the events that render to
//! attack traffic. The [`super::engine::ScenarioEngine`] walks it one step per
//! burst.
//!
//! Events use a flat shape (an `emit` kind plus optional parameter fields)
//! rather than an internally-tagged enum, which parses inconsistently across
//! YAML libraries -- the same convention the replay config uses for rate/gap.

use serde::Deserialize;

/// A whole attack timeline.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Playbook {
    pub phases: Vec<Phase>,
}

impl Playbook {
    pub fn parse(text: &str) -> Result<Self, String> {
        let pb: Playbook =
            serde_norway::from_str(text).map_err(|e| format!("parsing playbook: {e}"))?;
        if pb.phases.is_empty() {
            return Err("playbook has no phases".into());
        }
        Ok(pb)
    }

    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading playbook {}: {e}", path.display()))?;
        Self::parse(&text)
    }
}

/// One stage of the attack.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Phase {
    /// Short stable id, e.g. "manipulation".
    pub id: String,
    /// Human label for the status readout.
    #[serde(default)]
    pub name: Option<String>,
    /// ATT&CK-for-ICS technique ids this phase represents, e.g. ["T0843"].
    #[serde(default)]
    pub techniques: Vec<String>,
    /// Minimum announce bursts to dwell in this phase before advancing.
    #[serde(default = "default_dwell")]
    pub dwell_runs: u64,
    /// The attack actions emitted while in this phase.
    #[serde(default)]
    pub events: Vec<Event>,
}

fn default_dwell() -> u64 {
    1
}

/// One attack action. The `emit` kind selects the synth builder; the remaining
/// fields are its parameters (only those relevant to the kind are read).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub emit: EmitKind,
    /// The plant device this action targets (by ip, model, or asset_type).
    #[serde(default)]
    pub target: Option<DeviceRef>,
    // OT action parameters.
    #[serde(default)]
    pub value: Option<u16>,
    #[serde(default)]
    pub register: Option<u16>,
    #[serde(default)]
    pub db: Option<u16>,
    #[serde(default)]
    pub offset: Option<u16>,
    #[serde(default)]
    pub unit: Option<u8>,
    #[serde(default)]
    pub ioa: Option<u32>,
    #[serde(default)]
    pub common_addr: Option<u16>,
    /// A DNP3 control-point index, for `dnp3_operate`.
    #[serde(default)]
    pub point: Option<u16>,
    #[serde(default)]
    pub close: Option<bool>,
    #[serde(default)]
    pub block_id: Option<String>,
    #[serde(default)]
    pub payload_hex: Option<String>,
    #[serde(default)]
    pub chunk: Option<usize>,
    // IOC parameters.
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub share: Option<String>,
}

/// Which synth builder an event drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmitKind {
    /// Read an S7 CPU's identity (recon).
    S7Read,
    /// S7 block program-download sequence (logic injection).
    S7ProgramDownload,
    /// S7 write-var into a data block (rogue setpoint).
    S7Write,
    /// S7 PLC STOP.
    S7Stop,
    /// Modbus write register (setpoint manipulation).
    ModbusWrite,
    /// TriStation control-processor status poll (recon).
    TristationStatus,
    /// TriStation program download (implant delivery).
    TristationDownload,
    /// IEC-104 station interrogation (recon).
    Iec104Interrogation,
    /// IEC-104 single command (breaker open/close).
    Iec104Command,
    /// DNP3 integrity poll (recon).
    Dnp3Read,
    /// DNP3 SELECT-then-OPERATE control-relay-output block (breaker trip).
    Dnp3Operate,
    /// EtherNet/IP CIP Get_Attribute_Single (connected-session recon).
    CipRead,
    /// EtherNet/IP CIP Set_Attribute_Single (attribute write / manipulation).
    CipWrite,
    /// OPC-UA HELLO/ACKNOWLEDGE handshake (server discovery / recon).
    OpcuaRead,
    /// IEC 60870-5-101 station interrogation (recon).
    Iec101Interrogation,
    /// IEC 60870-5-101 single command (breaker open/close).
    Iec101Command,
    /// C2 beacon: resolve the actor domain and contact its address.
    C2Beacon,
    /// Inbound remote-access session (TeamViewer/VPN).
    RemoteAccess,
    /// Wiper write to a network share (KillDisk).
    Wiper,
    /// Serial-converter firmware overwrite (Moxa brick).
    MoxaBrick,
}

/// How an event selects a plant device. First match wins, checked ip -> model ->
/// asset_type, so a precise ip pins one device while a model/asset_type matches
/// the first of its kind.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRef {
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub asset_type: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_phased_playbook() {
        let yaml = "
phases:
  - id: recon
    name: PLC enumeration
    techniques: [T0842, T0888]
    dwell_runs: 2
    events:
      - { emit: s7_read, target: { model: 'SIMATIC S7-300 CPU 315-2 PN/DP' } }
  - id: sabotage
    name: Rogue setpoint
    techniques: [T0836, T0831]
    events:
      - { emit: s7_write, target: { ip: 10.20.10.11 }, db: 1, offset: 0, value: 1410 }
      - { emit: c2_beacon, domain: www.mypremierfutbol.com }
";
        let pb = Playbook::parse(yaml).expect("parses");
        assert_eq!(pb.phases.len(), 2);
        assert_eq!(pb.phases[0].id, "recon");
        assert_eq!(pb.phases[0].dwell_runs, 2);
        assert_eq!(pb.phases[0].events[0].emit, EmitKind::S7Read);
        let sab = &pb.phases[1];
        assert_eq!(sab.dwell_runs, 1, "dwell defaults to 1");
        assert_eq!(sab.events[0].emit, EmitKind::S7Write);
        assert_eq!(sab.events[0].value, Some(1410));
        assert_eq!(sab.events[1].emit, EmitKind::C2Beacon);
    }

    #[test]
    fn empty_playbook_and_unknown_field_are_errors() {
        assert!(Playbook::parse("phases: []").is_err(), "no phases");
        let bad = "phases:\n  - id: x\n    bogus: 1\n";
        assert!(Playbook::parse(bad).is_err(), "deny_unknown_fields");
        let bad_kind = "phases:\n  - id: x\n    events:\n      - { emit: nope }\n";
        assert!(Playbook::parse(bad_kind).is_err(), "unknown emit kind");
    }
}
