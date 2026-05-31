# Licenses

ot-turbolaser is MIT licensed. See `LICENSE`.

## Runtime and build dependencies

All crate dependencies are permissively licensed (MIT or Apache-2.0 or both).
Run `cargo tree` for the resolved set and `cargo deny` (if installed) to audit
licenses. The notable ones:

- clap, serde, serde_json, toml, rand, rand_distr, rand_chacha, glob, log,
  env_logger, signal-hook, ipnet: MIT or Apache-2.0.
- serde_norway: maintained fork of the archived serde_yaml, MIT or Apache-2.0.
- pcap-file: MIT or Apache-2.0.
- crc: MIT or Apache-2.0. Provides the predefined CRC_16_DNP algorithm used by
  the DNP3 mutator.

## Protocol references used while implementing the mutators

There is no permissively licensed Rust packet dissector for Modbus, EtherNet/IP
and CIP, S7comm, or DNP3. The mutators in this repo are implemented from public
protocol specifications and Wireshark dissector field semantics. The following
projects were read as references only. None of their code is vendored or copied
into this repo, because their licenses are incompatible with this MIT project:

- rmodbus: Apache-2.0. A Modbus server framework. Read for MBAP layout.
- s7-comm: non-standard, unvetted license. Read for S7 layer struct shapes.
- stepfunc/dnp3: non-commercial and non-production license. Read for DNP3
  framing and CRC correctness only.
- Suricata Rust app-layer parsers (DNP3, ENIP): GPLv2. Read as a correctness
  oracle only.

Forged output is validated against Wireshark's dissectors via tshark, which is
the authoritative ground truth for whether a passive sensor will accept it.
