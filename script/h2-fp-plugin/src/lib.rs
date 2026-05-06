use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_HEADER_LEN: usize = 9;
const MAX_BUFFER_BYTES: usize = 64 * 1024;
const FINALIZE_AFTER_FRAMES: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct H2Fingerprint {
    pub fp: String,
    pub settings: String,
    pub window: String,
    pub priority: String,
}

#[derive(Debug, Default)]
pub struct H2FrameExtractor {
    buffer: Vec<u8>,
    preface_seen: bool,
    non_h2: bool,
    frame_count: usize,
    settings: Option<String>,
    window: Option<String>,
    priority: Option<String>,
}

impl H2FrameExtractor {
    pub fn ingest(&mut self, data: &[u8], end_of_stream: bool) -> Option<H2Fingerprint> {
        if self.non_h2 {
            return Some(H2Fingerprint::default());
        }

        if !data.is_empty() {
            self.buffer.extend_from_slice(data);
            if self.buffer.len() > MAX_BUFFER_BYTES {
                let drop_len = self.buffer.len() - MAX_BUFFER_BYTES;
                self.buffer.drain(0..drop_len);
            }
        }

        self.parse_available();

        if self.ready_to_finalize(end_of_stream) {
            return Some(self.build_fingerprint());
        }

        None
    }

    fn parse_available(&mut self) {
        loop {
            if !self.preface_seen {
                if self.buffer.len() < H2_PREFACE.len() {
                    return;
                }
                if !self.buffer.starts_with(H2_PREFACE) {
                    self.non_h2 = true;
                    self.buffer.clear();
                    return;
                }
                self.preface_seen = true;
                self.buffer.drain(0..H2_PREFACE.len());
            }

            if self.buffer.len() < FRAME_HEADER_LEN {
                return;
            }

            let payload_len = ((self.buffer[0] as usize) << 16)
                | ((self.buffer[1] as usize) << 8)
                | (self.buffer[2] as usize);
            let frame_type = self.buffer[3];
            let flags = self.buffer[4];
            let stream_id = (u32::from_be_bytes([
                self.buffer[5],
                self.buffer[6],
                self.buffer[7],
                self.buffer[8],
            ]))
                & 0x7fff_ffff;

            let total_len = FRAME_HEADER_LEN + payload_len;
            if self.buffer.len() < total_len {
                return;
            }

            let payload = self.buffer[FRAME_HEADER_LEN..total_len].to_vec();
            self.handle_frame(frame_type, flags, stream_id, &payload);
            self.frame_count += 1;
            self.buffer.drain(0..total_len);
        }
    }

    fn handle_frame(&mut self, frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) {
        match frame_type {
            // SETTINGS
            0x04 => {
                if self.settings.is_none()
                    && stream_id == 0
                    && (flags & 0x01) == 0
                    && payload.len() % 6 == 0
                {
                    self.settings = Some(canonical_settings(payload));
                }
            }
            // WINDOW_UPDATE
            0x08 => {
                if self.window.is_none() && payload.len() == 4 {
                    let raw = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                    let increment = raw & 0x7fff_ffff;
                    if increment > 0 {
                        self.window = Some(increment.to_string());
                    }
                }
            }
            // PRIORITY
            0x02 => {
                if self.priority.is_none() && payload.len() == 5 {
                    self.priority = Some(canonical_priority(payload));
                }
            }
            _ => {}
        }
    }

    fn ready_to_finalize(&self, end_of_stream: bool) -> bool {
        if self.non_h2 {
            return true;
        }

        if !self.preface_seen {
            return end_of_stream;
        }

        if self.settings.is_some() && self.window.is_some() && self.priority.is_some() {
            return true;
        }

        if self.settings.is_some() && self.frame_count >= FINALIZE_AFTER_FRAMES {
            return true;
        }

        end_of_stream
    }

    fn build_fingerprint(&self) -> H2Fingerprint {
        let settings = self.settings.clone().unwrap_or_default();
        let window = self.window.clone().unwrap_or_default();
        let priority = self.priority.clone().unwrap_or_default();

        let canonical = format!("{}|{}|{}", settings, window, priority);
        let fp = sha256_hex(&canonical);

        H2Fingerprint {
            fp,
            settings,
            window,
            priority,
        }
    }
}

fn canonical_settings(payload: &[u8]) -> String {
    let mut map: BTreeMap<u16, u32> = BTreeMap::new();
    for chunk in payload.chunks_exact(6) {
        let id = u16::from_be_bytes([chunk[0], chunk[1]]);
        let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
        map.insert(id, value);
    }

    let mut out = Vec::with_capacity(map.len());
    for (id, value) in map {
        out.push(format!("{}={}", settings_name(id), value));
    }
    out.join(";")
}

fn settings_name(id: u16) -> &'static str {
    match id {
        1 => "header_table_size",
        2 => "enable_push",
        3 => "max_concurrent_streams",
        4 => "initial_window_size",
        5 => "max_frame_size",
        6 => "max_header_list_size",
        _ => "unknown",
    }
}

fn canonical_priority(payload: &[u8]) -> String {
    let raw = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let exclusive = (raw & 0x8000_0000) != 0;
    let dependency = raw & 0x7fff_ffff;
    let weight = u16::from(payload[4]) + 1;
    format!(
        "exclusive={};dependency={};weight={}",
        if exclusive { 1 } else { 0 },
        dependency,
        weight
    )
}

fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(target_arch = "wasm32")]
mod wasm_filter {
    use super::{H2Fingerprint, H2FrameExtractor};
    use proxy_wasm::traits::*;
    use proxy_wasm::types::*;

    proxy_wasm::main! {{
        proxy_wasm::set_log_level(LogLevel::Info);
        proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
            Box::new(H2Root)
        });
    }}

    struct H2Root;

    impl Context for H2Root {}

    impl RootContext for H2Root {
        fn get_type(&self) -> Option<ContextType> {
            Some(ContextType::StreamContext)
        }

        fn create_stream_context(&self, _context_id: u32) -> Option<Box<dyn StreamContext>> {
            Some(Box::new(H2Stream {
                extractor: H2FrameExtractor::default(),
                emitted: false,
            }))
        }
    }

    struct H2Stream {
        extractor: H2FrameExtractor,
        emitted: bool,
    }

    impl Context for H2Stream {}

    impl StreamContext for H2Stream {
        fn on_downstream_data(&mut self, data_size: usize, end_of_stream: bool) -> Action {
            if self.emitted {
                return Action::Continue;
            }

            let Some(data) = self.get_downstream_data(0, data_size) else {
                return Action::Continue;
            };

            if let Some(fp) = self.extractor.ingest(&data, end_of_stream) {
                self.emit_metadata(&fp);
                self.emitted = true;
            }

            Action::Continue
        }

        fn on_downstream_close(&mut self, _peer_type: PeerType) {
            if self.emitted {
                return;
            }
            let fp = self.extractor.ingest(&[], true).unwrap_or_default();
            self.emit_metadata(&fp);
            self.emitted = true;
        }
    }

    impl H2Stream {
        fn emit_metadata(&self, fp: &H2Fingerprint) {
            // StreamInfo dynamic metadata path used by %DYNAMIC_METADATA(namespace:key)%
            self.set_property(
                vec!["metadata", "filter_metadata", "gydev.h2", "fp"],
                Some(fp.fp.as_bytes()),
            );
            self.set_property(
                vec!["metadata", "filter_metadata", "gydev.h2", "settings"],
                Some(fp.settings.as_bytes()),
            );
            self.set_property(
                vec!["metadata", "filter_metadata", "gydev.h2", "window"],
                Some(fp.window.as_bytes()),
            );
            self.set_property(
                vec!["metadata", "filter_metadata", "gydev.h2", "priority"],
                Some(fp.priority.as_bytes()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{sha256_hex, H2FrameExtractor};

    fn frame_header(len: usize, frame_type: u8, flags: u8, stream_id: u32) -> Vec<u8> {
        vec![
            ((len >> 16) & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
            frame_type,
            flags,
            ((stream_id >> 24) as u8) & 0x7f,
            (stream_id >> 16) as u8,
            (stream_id >> 8) as u8,
            stream_id as u8,
        ]
    }

    fn settings_frame(entries: &[(u16, u32)]) -> Vec<u8> {
        let mut payload = Vec::new();
        for (id, val) in entries {
            payload.extend_from_slice(&id.to_be_bytes());
            payload.extend_from_slice(&val.to_be_bytes());
        }
        let mut frame = frame_header(payload.len(), 0x04, 0x00, 0);
        frame.extend_from_slice(&payload);
        frame
    }

    fn window_update_frame(increment: u32) -> Vec<u8> {
        let payload = (increment & 0x7fff_ffff).to_be_bytes();
        let mut frame = frame_header(4, 0x08, 0x00, 0);
        frame.extend_from_slice(&payload);
        frame
    }

    fn priority_frame(stream_id: u32, dependency: u32, exclusive: bool, weight: u8) -> Vec<u8> {
        let dep = if exclusive {
            dependency | 0x8000_0000
        } else {
            dependency & 0x7fff_ffff
        };
        let mut payload = Vec::with_capacity(5);
        payload.extend_from_slice(&dep.to_be_bytes());
        payload.push(weight.saturating_sub(1));
        let mut frame = frame_header(5, 0x02, 0x00, stream_id);
        frame.extend_from_slice(&payload);
        frame
    }

    #[test]
    fn extracts_settings_window_priority_and_sha256() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        bytes.extend_from_slice(&settings_frame(&[(4, 6291456), (1, 65536), (6, 262144)]));
        bytes.extend_from_slice(&window_update_frame(15663105));
        bytes.extend_from_slice(&priority_frame(3, 0, false, 16));

        let mut ex = H2FrameExtractor::default();
        let fp = ex.ingest(&bytes, false).expect("should finalize");

        assert_eq!(
            fp.settings,
            "header_table_size=65536;initial_window_size=6291456;max_header_list_size=262144"
        );
        assert_eq!(fp.window, "15663105");
        assert_eq!(fp.priority, "exclusive=0;dependency=0;weight=16");

        let expected = sha256_hex(
            "header_table_size=65536;initial_window_size=6291456;max_header_list_size=262144|15663105|exclusive=0;dependency=0;weight=16",
        );
        assert_eq!(fp.fp, expected);
        assert_eq!(fp.fp.len(), 64);
    }

    #[test]
    fn handles_missing_priority_as_empty() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        bytes.extend_from_slice(&settings_frame(&[(1, 4096), (4, 65535)]));
        bytes.extend_from_slice(&window_update_frame(983041));

        let mut ex = H2FrameExtractor::default();
        let fp = ex.ingest(&bytes, true).expect("end_of_stream finalize");

        assert_eq!(fp.settings, "header_table_size=4096;initial_window_size=65535");
        assert_eq!(fp.window, "983041");
        assert_eq!(fp.priority, "");
        assert_eq!(fp.fp.len(), 64);
    }

    #[test]
    fn handles_fragmented_input() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        bytes.extend_from_slice(&settings_frame(&[(1, 65536), (4, 65535)]));
        bytes.extend_from_slice(&window_update_frame(111111));

        let split = 19;
        let mut ex = H2FrameExtractor::default();
        let first = ex.ingest(&bytes[..split], false);
        assert!(first.is_none());

        let second = ex.ingest(&bytes[split..], true);
        let fp = second.expect("should finalize after second chunk");
        assert_eq!(fp.settings, "header_table_size=65536;initial_window_size=65535");
        assert_eq!(fp.window, "111111");
        assert_eq!(fp.fp.len(), 64);
    }

    #[test]
    fn non_h2_stream_returns_empty_fields() {
        let mut ex = H2FrameExtractor::default();
        let fp = ex.ingest(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", true).unwrap();
        assert_eq!(fp.settings, "");
        assert_eq!(fp.window, "");
        assert_eq!(fp.priority, "");
        assert_eq!(fp.fp, sha256_hex("||"));
    }
}
