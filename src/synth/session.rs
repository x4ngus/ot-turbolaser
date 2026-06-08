//! A synthesized TCP session.
//!
//! Emits a complete, established connection: the 3-way handshake, one or more
//! application request/response exchanges, then a graceful FIN teardown, with
//! sequence and acknowledgement numbers tracked correctly throughout. A passive
//! sensor (e.g. Zeek) attributes application identity only on connections it
//! saw established, so a lone mid-stream segment never fingerprints a device. The
//! handshake is what makes the identity stick.

use std::net::Ipv4Addr;

use super::eth::{tcp_segment, TCP_ACK, TCP_FIN, TCP_PSH, TCP_SYN};

/// One side of the conversation.
#[derive(Clone, Copy)]
enum Side {
    Client,
    Server,
}

/// Builds the frames of a single TCP connection between a client and a server,
/// keeping each side's send sequence in step so the handshake, data, and
/// teardown form a coherent, re-assemblable stream.
pub struct TcpSession {
    client_mac: [u8; 6],
    server_mac: [u8; 6],
    client_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    client_port: u16,
    server_port: u16,
    /// Next sequence number each side will send (its snd.nxt).
    client_snd: u32,
    server_snd: u32,
    frames: Vec<Vec<u8>>,
}

impl TcpSession {
    /// A new session with deterministic initial sequence numbers derived from
    /// the endpoints, so a given device's session is reproducible run to run and
    /// distinct sessions do not all start at the same ISN.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_mac: [u8; 6],
        server_mac: [u8; 6],
        client_ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        client_port: u16,
        server_port: u16,
    ) -> Self {
        let client_snd = u32::from(client_ip)
            .wrapping_mul(2_654_435_761)
            .wrapping_add(u32::from(client_port));
        let server_snd = u32::from(server_ip)
            .wrapping_mul(40_503)
            .wrapping_add(0x5EED_0000);
        Self {
            client_mac,
            server_mac,
            client_ip,
            server_ip,
            client_port,
            server_port,
            client_snd,
            server_snd,
            frames: Vec::new(),
        }
    }

    /// Emit one segment from `from`, advancing that side's sequence by the bytes
    /// it consumes (payload length, plus one for a SYN or FIN). The ack always
    /// reflects everything received from the peer so far (the peer's snd.nxt).
    fn segment(&mut self, from: Side, flags: u8, payload: &[u8]) {
        let (snd, peer_snd) = match from {
            Side::Client => (self.client_snd, self.server_snd),
            Side::Server => (self.server_snd, self.client_snd),
        };
        let (src_mac, dst_mac, src, dst, sport, dport) = match from {
            Side::Client => (
                self.client_mac,
                self.server_mac,
                self.client_ip,
                self.server_ip,
                self.client_port,
                self.server_port,
            ),
            Side::Server => (
                self.server_mac,
                self.client_mac,
                self.server_ip,
                self.client_ip,
                self.server_port,
                self.client_port,
            ),
        };
        self.frames.push(tcp_segment(
            src_mac, dst_mac, src, dst, sport, dport, snd, peer_snd, flags, payload,
        ));
        let consumed = payload.len() as u32 + u32::from(flags & (TCP_SYN | TCP_FIN) != 0);
        match from {
            Side::Client => self.client_snd = self.client_snd.wrapping_add(consumed),
            Side::Server => self.server_snd = self.server_snd.wrapping_add(consumed),
        }
    }

    /// The 3-way handshake: SYN, SYN+ACK, ACK.
    pub fn open(&mut self) {
        self.segment(Side::Client, TCP_SYN, &[]);
        self.segment(Side::Server, TCP_SYN | TCP_ACK, &[]);
        self.segment(Side::Client, TCP_ACK, &[]);
    }

    /// A client-to-server application message (PSH+ACK).
    pub fn client_says(&mut self, payload: &[u8]) {
        self.segment(Side::Client, TCP_PSH | TCP_ACK, payload);
    }

    /// A server-to-client application message (PSH+ACK).
    pub fn server_says(&mut self, payload: &[u8]) {
        self.segment(Side::Server, TCP_PSH | TCP_ACK, payload);
    }

    /// A graceful four-way close initiated by the client.
    pub fn close(&mut self) {
        self.segment(Side::Client, TCP_FIN | TCP_ACK, &[]);
        self.segment(Side::Server, TCP_ACK, &[]);
        self.segment(Side::Server, TCP_FIN | TCP_ACK, &[]);
        self.segment(Side::Client, TCP_ACK, &[]);
    }

    /// The accumulated frames in send order.
    pub fn into_frames(self) -> Vec<Vec<u8>> {
        self.frames
    }
}

/// A one-shot request/response TCP exchange: handshake, the client's request,
/// the server's response, then a graceful close. The common shape for a
/// single-PDU OT identity read or register write.
#[allow(clippy::too_many_arguments)]
pub fn request_response(
    client_mac: [u8; 6],
    server_mac: [u8; 6],
    client_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    client_port: u16,
    server_port: u16,
    request: &[u8],
    response: &[u8],
) -> Vec<Vec<u8>> {
    let mut s = TcpSession::new(
        client_mac,
        server_mac,
        client_ip,
        server_ip,
        client_port,
        server_port,
    );
    s.open();
    s.client_says(request);
    s.server_says(response);
    s.close();
    s.into_frames()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::{checksums_valid, parse_layout, L4Kind};

    fn tcp_at(buf: &[u8]) -> usize {
        parse_layout(buf).unwrap().l4
    }

    fn flags(buf: &[u8]) -> u8 {
        buf[tcp_at(buf) + 13]
    }
    fn seq(buf: &[u8]) -> u32 {
        let o = tcp_at(buf) + 4;
        u32::from_be_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]])
    }
    fn ack(buf: &[u8]) -> u32 {
        let o = tcp_at(buf) + 8;
        u32::from_be_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]])
    }

    fn session() -> Vec<Vec<u8>> {
        let mut s = TcpSession::new(
            [0x02, 0, 0, 0, 0, 1],
            [0x02, 0, 0, 0, 0, 2],
            Ipv4Addr::new(10, 0, 0, 250),
            Ipv4Addr::new(10, 0, 0, 5),
            50000,
            502,
        );
        s.open();
        s.client_says(b"request");
        s.server_says(b"a-longer-response");
        s.close();
        s.into_frames()
    }

    #[test]
    fn handshake_then_data_then_teardown() {
        let f = session();
        // 3 handshake + 2 data + 4 teardown.
        assert_eq!(f.len(), 9);
        assert_eq!(flags(&f[0]), TCP_SYN, "SYN");
        assert_eq!(flags(&f[1]), TCP_SYN | TCP_ACK, "SYN+ACK");
        assert_eq!(flags(&f[2]), TCP_ACK, "ACK");
        assert_eq!(flags(&f[3]), TCP_PSH | TCP_ACK, "client data");
        assert_eq!(flags(&f[4]), TCP_PSH | TCP_ACK, "server data");
        assert_eq!(flags(&f[5]), TCP_FIN | TCP_ACK, "client FIN");
        assert_eq!(flags(&f[8]), TCP_ACK, "final ACK");
        for p in &f {
            let l = parse_layout(p).unwrap();
            assert_eq!(l.l4_kind, L4Kind::Tcp);
            assert!(checksums_valid(p, &l), "every segment checksums valid");
        }
    }

    #[test]
    fn sequence_and_ack_numbers_track_the_stream() {
        let f = session();
        // After the SYN handshake each ISN is consumed by one.
        let c_isn = seq(&f[0]);
        let s_isn = seq(&f[1]);
        assert_eq!(ack(&f[1]), c_isn.wrapping_add(1), "SYN+ACK acks the SYN");
        assert_eq!(ack(&f[2]), s_isn.wrapping_add(1), "ACK acks the SYN+ACK");
        // Client data starts at ISN+1 and the server acks past the 7 request bytes.
        assert_eq!(seq(&f[3]), c_isn.wrapping_add(1), "client data seq");
        assert_eq!(seq(&f[4]), s_isn.wrapping_add(1), "server data seq");
        assert_eq!(
            ack(&f[4]),
            c_isn.wrapping_add(1 + 7),
            "server acks the 7 request bytes"
        );
        // Client FIN seq is past its own data; the final exchange acks both FINs.
        assert_eq!(seq(&f[5]), c_isn.wrapping_add(1 + 7), "client FIN seq");
        assert_eq!(
            ack(&f[5]),
            s_isn.wrapping_add(1 + 17),
            "client acks the 17 response bytes"
        );
    }
}
