//! Offset-checked access to L2 through L4 of one captured frame, with in-place
//! IPv4 and TCP/UDP checksum recompute.
//!
//! Hand-rolled rather than pulling in a parsing crate: the job is narrow (find
//! a few offsets, edit fixed-width fields, fix checksums) and a small parser we
//! own is stable and fully testable. IPv4 only; IPv6 and non-IP frames are
//! recognised as Other and left untouched, which is safe (the mutator simply
//! does not match them).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L3Kind {
    Ipv4,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L4Kind {
    Tcp,
    Udp,
    Other,
}

/// Byte offsets into a frame buffer. `end` is the end of the IP packet within
/// the buffer, excluding any Ethernet padding, so checksums and payload slices
/// cover exactly the IP payload.
#[derive(Clone, Copy, Debug)]
pub struct FrameLayout {
    pub l3: usize,
    pub l3_kind: L3Kind,
    pub ihl: usize,
    pub l4: usize,
    pub l4_kind: L4Kind,
    pub payload: usize,
    pub end: usize,
}

/// Parse Ethernet (with any number of VLAN tags) then IPv4 then TCP/UDP.
/// Returns None for frames too short or malformed to mutate safely.
pub fn parse_layout(buf: &[u8]) -> Option<FrameLayout> {
    if buf.len() < 14 {
        return None;
    }
    let mut off = 12;
    let mut ethertype = u16::from_be_bytes([buf[off], buf[off + 1]]);
    off += 2;
    let mut guard = 0;
    while (ethertype == 0x8100 || ethertype == 0x88a8) && guard < 4 {
        if buf.len() < off + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
        off += 4;
        guard += 1;
    }
    let l3 = off;
    if ethertype == 0x0800 {
        parse_ipv4(buf, l3)
    } else {
        Some(FrameLayout {
            l3,
            l3_kind: L3Kind::Other,
            ihl: 0,
            l4: l3,
            l4_kind: L4Kind::Other,
            payload: l3,
            end: buf.len(),
        })
    }
}

fn parse_ipv4(buf: &[u8], l3: usize) -> Option<FrameLayout> {
    if buf.len() < l3 + 20 {
        return None;
    }
    let vihl = buf[l3];
    if vihl >> 4 != 4 {
        return None;
    }
    let ihl = ((vihl & 0x0f) as usize) * 4;
    if ihl < 20 || buf.len() < l3 + ihl {
        return None;
    }
    let ip_total = u16::from_be_bytes([buf[l3 + 2], buf[l3 + 3]]) as usize;
    if ip_total < ihl {
        return None;
    }
    let end = (l3 + ip_total).min(buf.len());
    let proto = buf[l3 + 9];
    let l4 = l3 + ihl;
    let (l4_kind, l4_hdr) = match proto {
        6 => {
            if buf.len() < l4 + 20 {
                return None;
            }
            let data_off = ((buf[l4 + 12] >> 4) as usize) * 4;
            if data_off < 20 || buf.len() < l4 + data_off {
                return None;
            }
            (L4Kind::Tcp, data_off)
        }
        17 => {
            if buf.len() < l4 + 8 {
                return None;
            }
            (L4Kind::Udp, 8)
        }
        _ => (L4Kind::Other, 0),
    };
    let payload = (l4 + l4_hdr).min(end);
    Some(FrameLayout {
        l3,
        l3_kind: L3Kind::Ipv4,
        ihl,
        l4,
        l4_kind,
        payload,
        end,
    })
}

/// Recompute the IPv4 header checksum and the TCP/UDP checksum in place. A
/// no-op for non-IPv4 frames.
pub fn recompute_checksums(buf: &mut [u8], l: &FrameLayout) {
    if l.l3_kind != L3Kind::Ipv4 {
        return;
    }
    buf[l.l3 + 10] = 0;
    buf[l.l3 + 11] = 0;
    let mut s = 0u32;
    sum_words(&mut s, &buf[l.l3..l.l3 + l.ihl]);
    let ipck = !fold(s);
    buf[l.l3 + 10] = (ipck >> 8) as u8;
    buf[l.l3 + 11] = (ipck & 0xff) as u8;
    match l.l4_kind {
        L4Kind::Tcp => l4_checksum(buf, l, 16),
        L4Kind::Udp => l4_checksum(buf, l, 6),
        L4Kind::Other => {}
    }
}

/// True if the IPv4 header checksum and the TCP/UDP checksum both validate.
/// Non-IPv4 frames are reported valid (nothing for us to check).
pub fn checksums_valid(buf: &[u8], l: &FrameLayout) -> bool {
    if l.l3_kind != L3Kind::Ipv4 {
        return true;
    }
    let mut s = 0u32;
    sum_words(&mut s, &buf[l.l3..l.l3 + l.ihl]);
    if fold(s) != 0xffff {
        return false;
    }
    match l.l4_kind {
        L4Kind::Tcp | L4Kind::Udp => {
            let src = &buf[l.l3 + 12..l.l3 + 16];
            let dst = &buf[l.l3 + 16..l.l3 + 20];
            let proto = buf[l.l3 + 9];
            let l4_len = l.end - l.l4;
            let pseudo = [
                src[0],
                src[1],
                src[2],
                src[3],
                dst[0],
                dst[1],
                dst[2],
                dst[3],
                0,
                proto,
                (l4_len >> 8) as u8,
                (l4_len & 0xff) as u8,
            ];
            let mut s = 0u32;
            sum_words(&mut s, &pseudo);
            sum_words(&mut s, &buf[l.l4..l.end]);
            fold(s) == 0xffff
        }
        L4Kind::Other => true,
    }
}

fn l4_checksum(buf: &mut [u8], l: &FrameLayout, csum_off: usize) {
    if l.end <= l.l4 || l.l4 + csum_off + 1 >= buf.len() {
        return;
    }
    let src = [
        buf[l.l3 + 12],
        buf[l.l3 + 13],
        buf[l.l3 + 14],
        buf[l.l3 + 15],
    ];
    let dst = [
        buf[l.l3 + 16],
        buf[l.l3 + 17],
        buf[l.l3 + 18],
        buf[l.l3 + 19],
    ];
    let proto = buf[l.l3 + 9];
    let l4_len = l.end - l.l4;
    buf[l.l4 + csum_off] = 0;
    buf[l.l4 + csum_off + 1] = 0;
    let pseudo = [
        src[0],
        src[1],
        src[2],
        src[3],
        dst[0],
        dst[1],
        dst[2],
        dst[3],
        0,
        proto,
        (l4_len >> 8) as u8,
        (l4_len & 0xff) as u8,
    ];
    let mut s = 0u32;
    sum_words(&mut s, &pseudo);
    sum_words(&mut s, &buf[l.l4..l.end]);
    let mut csum = !fold(s);
    if l.l4_kind == L4Kind::Udp && csum == 0 {
        csum = 0xffff;
    }
    buf[l.l4 + csum_off] = (csum >> 8) as u8;
    buf[l.l4 + csum_off + 1] = (csum & 0xff) as u8;
}

fn sum_words(acc: &mut u32, data: &[u8]) {
    let mut i = 0;
    while i + 1 < data.len() {
        *acc += ((data[i] as u32) << 8) | data[i + 1] as u32;
        i += 2;
    }
    if i < data.len() {
        *acc += (data[i] as u32) << 8;
    }
}

fn fold(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

/// A parsed frame: a mutable view of the buffer plus its layout. Mutators edit
/// the payload; the reload pipeline calls [`ParsedFrame::recompute_checksums`].
pub struct ParsedFrame<'a> {
    pub buf: &'a mut [u8],
    pub layout: FrameLayout,
}

impl<'a> ParsedFrame<'a> {
    pub fn parse(buf: &'a mut [u8]) -> Option<Self> {
        let layout = parse_layout(buf)?;
        Some(Self { buf, layout })
    }

    pub fn is_ipv4(&self) -> bool {
        self.layout.l3_kind == L3Kind::Ipv4
    }

    pub fn l4_kind(&self) -> L4Kind {
        self.layout.l4_kind
    }

    pub fn payload(&self) -> &[u8] {
        &self.buf[self.layout.payload..self.layout.end]
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        let (p, e) = (self.layout.payload, self.layout.end);
        &mut self.buf[p..e]
    }

    pub fn ipv4_src(&self) -> Option<[u8; 4]> {
        let l = self.layout.l3;
        self.is_ipv4().then(|| {
            [
                self.buf[l + 12],
                self.buf[l + 13],
                self.buf[l + 14],
                self.buf[l + 15],
            ]
        })
    }

    pub fn ipv4_dst(&self) -> Option<[u8; 4]> {
        let l = self.layout.l3;
        self.is_ipv4().then(|| {
            [
                self.buf[l + 16],
                self.buf[l + 17],
                self.buf[l + 18],
                self.buf[l + 19],
            ]
        })
    }

    pub fn set_ipv4_src(&mut self, a: [u8; 4]) {
        if self.is_ipv4() {
            let l = self.layout.l3;
            self.buf[l + 12..l + 16].copy_from_slice(&a);
        }
    }

    pub fn set_ipv4_dst(&mut self, a: [u8; 4]) {
        if self.is_ipv4() {
            let l = self.layout.l3;
            self.buf[l + 16..l + 20].copy_from_slice(&a);
        }
    }

    /// Destination MAC (Ethernet bytes 0..6). The buffer always starts with the
    /// Ethernet header; `parse_layout` guarantees at least 14 bytes.
    pub fn dst_mac(&self) -> [u8; 6] {
        let mut m = [0u8; 6];
        m.copy_from_slice(&self.buf[0..6]);
        m
    }

    /// Source MAC (Ethernet bytes 6..12).
    pub fn src_mac(&self) -> [u8; 6] {
        let mut m = [0u8; 6];
        m.copy_from_slice(&self.buf[6..12]);
        m
    }

    /// Rewrite the destination MAC. No checksum recompute needed: the captured
    /// frame carries no FCS and MAC bytes are outside the IP/L4 checksum scope.
    pub fn set_dst_mac(&mut self, m: [u8; 6]) {
        self.buf[0..6].copy_from_slice(&m);
    }

    /// Rewrite the source MAC. Used by red-laser device fabrication and threat
    /// promotion to assign a vendor or harvested desktop OUI.
    pub fn set_src_mac(&mut self, m: [u8; 6]) {
        self.buf[6..12].copy_from_slice(&m);
    }

    pub fn src_port(&self) -> Option<u16> {
        match self.layout.l4_kind {
            L4Kind::Tcp | L4Kind::Udp => {
                let l = self.layout.l4;
                Some(u16::from_be_bytes([self.buf[l], self.buf[l + 1]]))
            }
            L4Kind::Other => None,
        }
    }

    pub fn dst_port(&self) -> Option<u16> {
        match self.layout.l4_kind {
            L4Kind::Tcp | L4Kind::Udp => {
                let l = self.layout.l4;
                Some(u16::from_be_bytes([self.buf[l + 2], self.buf[l + 3]]))
            }
            L4Kind::Other => None,
        }
    }

    pub fn recompute_checksums(&mut self) {
        recompute_checksums(self.buf, &self.layout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build Ethernet + IPv4 + UDP with the given payload, checksums filled in.
    fn udp_packet(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0x52, 0x54, 0, 0, 0, 1]); // dst mac
        b.extend_from_slice(&[0x52, 0x54, 0, 0, 0, 2]); // src mac
        b.extend_from_slice(&[0x08, 0x00]); // ethertype IPv4
        let ip_start = b.len();
        let udp_len = 8 + payload.len();
        let ip_total = 20 + udp_len;
        b.extend_from_slice(&[0x45, 0x00]); // ver/ihl, dscp
        b.extend_from_slice(&(ip_total as u16).to_be_bytes());
        b.extend_from_slice(&[0x00, 0x00, 0x40, 0x00]); // id, flags/frag
        b.extend_from_slice(&[0x40, 17]); // ttl, proto=UDP
        b.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        b.extend_from_slice(&src);
        b.extend_from_slice(&dst);
        b.extend_from_slice(&sport.to_be_bytes());
        b.extend_from_slice(&dport.to_be_bytes());
        b.extend_from_slice(&(udp_len as u16).to_be_bytes());
        b.extend_from_slice(&[0x00, 0x00]); // udp checksum placeholder
        b.extend_from_slice(payload);
        let _ = ip_start;
        let layout = parse_layout(&b).unwrap();
        recompute_checksums(&mut b, &layout);
        b
    }

    // Verify a frame's checksums hold: the ones-complement sum including the
    // checksum field folds to all ones.
    fn ip_checksum_valid(buf: &[u8], l: &FrameLayout) -> bool {
        let mut s = 0u32;
        sum_words(&mut s, &buf[l.l3..l.l3 + l.ihl]);
        fold(s) == 0xffff
    }

    fn udp_checksum_valid(buf: &[u8], l: &FrameLayout) -> bool {
        let src = &buf[l.l3 + 12..l.l3 + 16];
        let dst = &buf[l.l3 + 16..l.l3 + 20];
        let l4_len = l.end - l.l4;
        let pseudo = [
            src[0],
            src[1],
            src[2],
            src[3],
            dst[0],
            dst[1],
            dst[2],
            dst[3],
            0,
            17,
            (l4_len >> 8) as u8,
            (l4_len & 0xff) as u8,
        ];
        let mut s = 0u32;
        sum_words(&mut s, &pseudo);
        sum_words(&mut s, &buf[l.l4..l.end]);
        fold(s) == 0xffff
    }

    #[test]
    fn ipv4_header_checksum_known_vector() {
        // Canonical example: header with checksum zeroed sums to 0xb861.
        let hdr: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let mut s = 0u32;
        sum_words(&mut s, &hdr);
        assert_eq!(!fold(s), 0xb861);
    }

    #[test]
    fn mac_accessors_read_and_write() {
        let mut p = udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1000, 502, b"x");
        let l = {
            let mut f = ParsedFrame::parse(&mut p).unwrap();
            assert_eq!(f.dst_mac(), [0x52, 0x54, 0, 0, 0, 1]);
            assert_eq!(f.src_mac(), [0x52, 0x54, 0, 0, 0, 2]);
            f.set_src_mac([0x00, 0x90, 0xE8, 0xAB, 0xCD, 0xEF]);
            f.recompute_checksums();
            f.layout
        };
        assert_eq!(&p[6..12], &[0x00, 0x90, 0xE8, 0xAB, 0xCD, 0xEF]);
        // IP/L4 checksums unaffected by the MAC edit.
        assert!(ip_checksum_valid(&p, &l));
        assert!(udp_checksum_valid(&p, &l));
    }

    #[test]
    fn parses_eth_ipv4_udp_offsets() {
        let p = udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1000, 502, b"hello");
        let l = parse_layout(&p).unwrap();
        assert_eq!(l.l3_kind, L3Kind::Ipv4);
        assert_eq!(l.l3, 14);
        assert_eq!(l.ihl, 20);
        assert_eq!(l.l4_kind, L4Kind::Udp);
        assert_eq!(l.l4, 34);
        assert_eq!(l.payload, 42);
        assert_eq!(&p[l.payload..l.end], b"hello");
    }

    #[test]
    fn parses_vlan_tagged_ipv4_tcp() {
        // Eth + 802.1Q VLAN + IPv4 + TCP (20-byte headers), 4-byte payload.
        let mut b = vec![0u8; 12];
        b.extend_from_slice(&[0x81, 0x00, 0x00, 0x0a]); // VLAN tag, vid 10
        b.extend_from_slice(&[0x08, 0x00]); // inner ethertype IPv4
        let ip_total = 20 + 20 + 4;
        b.extend_from_slice(&[0x45, 0x00]);
        b.extend_from_slice(&(ip_total as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0, 0x40, 0, 0x40, 6, 0, 0]); // id/frag/ttl/proto=TCP/csum
        b.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        b.extend_from_slice(&[0x1f, 0x90, 0x00, 0x50]); // ports
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // seq/ack
        b.extend_from_slice(&[0x50, 0x02, 0, 0, 0, 0, 0, 0]); // dataoff=5, flags, win, csum, urg
        b.extend_from_slice(&[1, 2, 3, 4]); // payload
        let l = parse_layout(&b).unwrap();
        assert_eq!(l.l3, 18); // 12 + 4 (vlan) + 2 (ethertype)
        assert_eq!(l.l4_kind, L4Kind::Tcp);
        assert_eq!(l.l4, 38);
        assert_eq!(l.payload, 58);
        assert_eq!(&b[l.payload..l.end], &[1, 2, 3, 4]);
    }

    #[test]
    fn recompute_is_idempotent_and_valid() {
        let mut p = udp_packet([192, 168, 1, 10], [192, 168, 1, 20], 4096, 20000, b"DNP3");
        let before = p.clone();
        let l = parse_layout(&p).unwrap();
        recompute_checksums(&mut p, &l);
        assert_eq!(p, before, "recomputing a valid frame must not change it");
        assert!(ip_checksum_valid(&p, &l));
        assert!(udp_checksum_valid(&p, &l));
    }

    #[test]
    fn remap_addr_then_recompute_stays_valid() {
        let mut p = udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1000, 502, b"payload-bytes");
        let l = {
            let mut f = ParsedFrame::parse(&mut p).unwrap();
            f.set_ipv4_src([172, 20, 7, 1]);
            f.set_ipv4_dst([172, 20, 7, 2]);
            f.recompute_checksums();
            f.layout
        };
        assert_eq!(&p[l.l3 + 12..l.l3 + 16], &[172, 20, 7, 1]);
        assert!(ip_checksum_valid(&p, &l));
        assert!(udp_checksum_valid(&p, &l));
    }
}
