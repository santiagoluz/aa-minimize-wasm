wit_bindgen::generate!({
    world: "packet-hook",
    path: "wit",
});

use crate::aa::packet::types::ProxyType;

use std::cell::Cell;
use std::time::Instant;

// Steering wheel button to intercept (set to your car's keycode)
const KEYCODE_TRIGGER: u32 = 65540;
// INPUT_MESSAGE_INPUT_REPORT message ID
const MSG_INPUT_REPORT: u16 = 0x8001;
// MEDIA_MESSAGE_VIDEO_FOCUS_NOTIFICATION message ID (sniffed to learn the video channel)
const MSG_VIDEO_FOCUS_NOTIFICATION: u16 = 0x8008;
// MEDIA_MESSAGE_VIDEO_FOCUS_REQUEST message ID (what we inject)
const MSG_VIDEO_FOCUS_REQUEST: u16 = 0x8007;
// Minimum hold duration to classify as a long press
const LONG_PRESS_MS: u128 = 500;

// VideoFocusRequestNotification { mode: VIDEO_FOCUS_NATIVE, reason: UNKNOWN }
// Byte-for-byte match with what the physical HU sends when the native exit button
// is tapped. Proto layout (protos.proto):
//   field 1 = disp_channel_id (deprecated, ignored)
//   field 2 = VideoFocusMode mode
//   field 3 = VideoFocusReason reason
// Encoding:
//   [0x80, 0x07]  message_id 0x8007
//   [0x10, 0x02]  tag=(field2, varint) value=2 (VIDEO_FOCUS_NATIVE)
//   [0x18, 0x00]  tag=(field3, varint) value=0 (UNKNOWN) — matches real HU output
const VIDEO_FOCUS_NATIVE_PAYLOAD: [u8; 6] = [0x80, 0x07, 0x10, 0x02, 0x18, 0x00];

// ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST — used by aa-proxy-rs for all
// injected single-frame packets.
const PKT_FLAGS_SINGLE: u8 = 0x0B;

// State machine for tracking a single button's press/release lifecycle.
// WASM is single-threaded, so Cell<_> is safe here.
#[derive(Copy, Clone)]
enum PressState {
    Idle,
    Pressed(Instant),
    Handled,
}

thread_local! {
    static STATE: Cell<PressState> = Cell::new(PressState::Idle);
    // Video channel learned from the first VIDEO_FOCUS_NOTIFICATION seen in
    // the session. Defaults to 0x11, which is the typical value.
    static VIDEO_CH: Cell<u8> = Cell::new(0x11);
    // Set to true on long press; cleared when the next HU→MD packet is replaced
    // with VIDEO_FOCUS_NATIVE so it flows to the phone.
    static PENDING_EXIT: Cell<bool> = Cell::new(false);
}

// ---------------------------------------------------------------------------
// Minimal protobuf parser — only extracts the first key's (keycode, down) from
// an InputReport payload. No external dependency needed.
// ---------------------------------------------------------------------------

fn read_varint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *data.get(*pos)?;
        *pos += 1;
        result |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

fn skip_field(data: &[u8], pos: &mut usize, wire_type: u64) -> Option<()> {
    match wire_type {
        0 => { read_varint(data, pos)?; }
        1 => { *pos = pos.checked_add(8).filter(|&p| p <= data.len())?; }
        2 => {
            let len = read_varint(data, pos)? as usize;
            *pos = pos.checked_add(len).filter(|&p| p <= data.len())?;
        }
        5 => { *pos = pos.checked_add(4).filter(|&p| p <= data.len())?; }
        _ => return None,
    }
    Some(())
}

// Parses the protobuf bytes of an InputReport (i.e. payload[2..] after the
// 2-byte message_id) and returns (keycode, down) for the first key found.
fn parse_key(data: &[u8]) -> Option<(u32, bool)> {
    let mut pos = 0;

    // Walk InputReport fields looking for field 4 (key_event).
    while pos < data.len() {
        let tag = read_varint(data, &mut pos)?;
        let (field, wire) = ((tag >> 3) as u32, tag & 0x7);

        if field == 4 && wire == 2 {
            // key_event: length-delimited KeyEvent message
            let ke_len = read_varint(data, &mut pos)? as usize;
            let ke_end = pos.checked_add(ke_len).filter(|&p| p <= data.len())?;

            // Walk KeyEvent fields looking for field 1 (keys).
            while pos < ke_end {
                let inner_tag = read_varint(data, &mut pos)?;
                let (i_field, i_wire) = ((inner_tag >> 3) as u32, inner_tag & 0x7);

                if i_field == 1 && i_wire == 2 {
                    // keys: length-delimited Key message
                    let key_len = read_varint(data, &mut pos)? as usize;
                    let key_end = pos.checked_add(key_len).filter(|&p| p <= data.len())?;

                    let mut keycode: Option<u32> = None;
                    let mut down: Option<bool> = None;

                    while pos < key_end {
                        let k_tag = read_varint(data, &mut pos)?;
                        let (k_field, k_wire) = ((k_tag >> 3) as u32, k_tag & 0x7);
                        match (k_field, k_wire) {
                            (1, 0) => keycode = Some(read_varint(data, &mut pos)? as u32),
                            (2, 0) => down = Some(read_varint(data, &mut pos)? != 0),
                            _ => skip_field(data, &mut pos, k_wire)?,
                        }
                    }

                    if let (Some(kc), Some(d)) = (keycode, down) {
                        return Some((kc, d));
                    }
                } else {
                    skip_field(data, &mut pos, i_wire)?;
                }
            }
        } else {
            skip_field(data, &mut pos, wire)?;
        }
    }

    None
}

// ---------------------------------------------------------------------------
// WIT guest implementation
// ---------------------------------------------------------------------------

struct Component;

impl Guest for Component {
    fn on_create() {
        aa::packet::host::info(&format!(
            "[aa-minimize] loaded: long-press keycode {} → VIDEO_FOCUS_NATIVE",
            KEYCODE_TRIGGER
        ));
    }

    fn on_destroy() {}

    fn custom_configs() -> Vec<CustomConfigSection> {
        Vec::new()
    }

    fn on_config_changed(_name: String, _value: String) {}

    fn modify_packet(_ctx: ModifyContext, pkt: Packet, _cfg: ConfigView) -> Decision {
        // Sniff VIDEO_FOCUS_NOTIFICATION to learn which channel the video stream
        // uses this session. The first one always arrives at AA connect time
        // (focus: VIDEO_FOCUS_PROJECTED) so VIDEO_CH is set before it's needed.
        if pkt.proxy_type == ProxyType::MobileDevice
            && pkt.message_id == MSG_VIDEO_FOCUS_NOTIFICATION
        {
            VIDEO_CH.with(|c| c.set(pkt.channel));
        }

        // ── Pending exit: inject VIDEO_FOCUS_REQUEST(NATIVE) to the phone ───────
        // replace-current rewrites the next HU→MD packet in-place so it flows
        // to the phone as a VIDEO_FOCUS_REQUEST. This mirrors the real exit-button
        // flow the phone expects: it stops projecting, keeps the TCP session alive,
        // and replies with VIDEO_FOCUS_NOTIFICATION(NATIVE, unsolicited:true).
        if pkt.proxy_type == ProxyType::HeadUnit && PENDING_EXIT.with(|p| p.get()) {
            let ch = VIDEO_CH.with(|c| c.get());
            PENDING_EXIT.with(|p| p.set(false));
            aa::packet::host::info(&format!(
                "[aa-minimize] injecting VIDEO_FOCUS_REQUEST(NATIVE) on ch {:#04x} payload={:02x?}",
                ch, &VIDEO_FOCUS_NATIVE_PAYLOAD
            ));
            aa::packet::host::replace_current(&Packet {
                proxy_type: ProxyType::HeadUnit,
                channel: ch,
                packet_flags: PKT_FLAGS_SINGLE,
                final_length: None,
                message_id: MSG_VIDEO_FOCUS_REQUEST,
                payload: VIDEO_FOCUS_NATIVE_PAYLOAD.to_vec(),
            });
            return Decision::Forward;
        }

        // ── Debug: log every key event with its direction ───────────────────
        if pkt.message_id == MSG_INPUT_REPORT && pkt.payload.len() >= 2 {
            if let Some((keycode, down)) = parse_key(&pkt.payload[2..]) {
                let dir = match pkt.proxy_type {
                    ProxyType::HeadUnit => "HU→MD",
                    ProxyType::MobileDevice => "MD→HU",
                };
                aa::packet::host::info(&format!(
                    "[aa-minimize] key dir={} keycode={} down={}",
                    dir, keycode, down
                ));
            }
        }

        // Only intercept phone → head-unit direction.
        // The HU sends a brief ~20ms pulse on every key-down regardless of hold
        // duration, so the HeadUnit direction cannot distinguish short from long.
        // The phone side streams repeated down=true events every ~50ms while the
        // button is held and emits down=false on release — giving accurate timing.
        if pkt.proxy_type != ProxyType::MobileDevice {
            return Decision::Forward;
        }

        // Only INPUT_MESSAGE_INPUT_REPORT packets.
        if pkt.message_id != MSG_INPUT_REPORT {
            return Decision::Forward;
        }

        // Payload: [msg_id_hi, msg_id_lo, proto...]
        if pkt.payload.len() < 2 {
            return Decision::Forward;
        }

        let Some((keycode, down)) = parse_key(&pkt.payload[2..]) else {
            return Decision::Forward;
        };

        if keycode != KEYCODE_TRIGGER {
            return Decision::Forward;
        }

        STATE.with(|s| {
            match (s.get(), down) {
                // ── Button pressed down ─────────────────────────────────────
                // Fresh press (or new press immediately after handling the previous one).
                (PressState::Idle, true) | (PressState::Handled, true) => {
                    aa::packet::host::info("[aa-minimize] state Idle→Pressed (tracking hold)");
                    s.set(PressState::Pressed(Instant::now()));
                    Decision::Drop
                }

                // Proxy sends each event twice; absorb the duplicate down / key-repeat.
                (PressState::Pressed(_), true) => Decision::Drop,

                // ── Button released ─────────────────────────────────────────
                (PressState::Pressed(start), false) => {
                    let elapsed_ms = start.elapsed().as_millis();
                    s.set(PressState::Handled);

                    if elapsed_ms >= LONG_PRESS_MS {
                        aa::packet::host::info(&format!(
                            "[aa-minimize] long press {}ms → scheduling VIDEO_FOCUS_NATIVE",
                            elapsed_ms
                        ));
                        PENDING_EXIT.with(|p| p.set(true));
                    } else {
                        // Short press: the HU's original pulse already reached the phone
                        // (HeadUnit direction is now unfiltered), so voice activates on its
                        // own — no re-injection needed.
                        aa::packet::host::info(&format!(
                            "[aa-minimize] short press {}ms → voice tap via HU pulse",
                            elapsed_ms
                        ));
                    }

                    // Either way, drop the original up; we already handled the action above.
                    Decision::Drop
                }

                // Proxy's duplicate up-event after we already acted — absorb and reset.
                (PressState::Handled, false) => {
                    s.set(PressState::Idle);
                    Decision::Drop
                }

                // Stray release with no tracked press (shouldn't happen normally).
                (PressState::Idle, false) => Decision::Forward,
            }
        })
    }

    fn ws_script_handler(_topic: String, _payload: String) -> String {
        String::new()
    }
}

export!(Component);
