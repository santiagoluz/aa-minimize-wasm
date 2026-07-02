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

// InputReport { timestamp:0, key_event { keys { keycode:KEYCODE_TRIGGER, down:X, metastate:0 } } }
// Used to re-inject the key pulse to the HU on short press, since we dropped all
// MD→HU events while waiting to classify the hold.
//
// Proto encoding (protos.proto field numbers):
//   InputReport  field 1 = timestamp (uint64)   field 4 = key_event (KeyEvent)
//   KeyEvent     field 1 = keys (Key)
//   Key          field 1 = keycode (uint32)      field 2 = down (bool)    field 3 = metastate (uint32)
//
//   [0x80, 0x01]              message_id 0x8001
//   [0x08, 0x00]              timestamp = 0
//   [0x22, 0x0A]              key_event length-delimited, 10 bytes
//   [0x0A, 0x08]              keys length-delimited, 8 bytes
//   [0x08, 0x84, 0x80, 0x04]  keycode = 65540 (varint: 4 | 0x80, 0 | 0x80, 4)
//   [0x10, 0x01 / 0x00]       down = true / false
//   [0x18, 0x00]              metastate = 0
//
// NOTE: hardcoded for KEYCODE_TRIGGER = 65540. If you change KEYCODE_TRIGGER
// you must also update the keycode varint bytes here. The matching key-up is
// not constructed synthetically — the real MD→HU down=false packet that
// triggered short-press detection is forwarded as-is.
const SHORT_PRESS_KEY_DOWN: [u8; 16] =
    [0x80, 0x01, 0x08, 0x00, 0x22, 0x0A, 0x0A, 0x08, 0x08, 0x84, 0x80, 0x04, 0x10, 0x01, 0x18, 0x00];

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

// Whether Android Auto currently has video focus. Used to gate interception:
// during calls or while AA is in the background the phone holds NATIVE focus
// and the PHONE button must pass through so call-management actions work.
#[derive(Copy, Clone, PartialEq)]
enum FocusState {
    Projected,
    Native,
}

thread_local! {
    static STATE: Cell<PressState> = Cell::new(PressState::Idle);
    // Video channel learned from the first VIDEO_FOCUS_NOTIFICATION seen in
    // the session. Defaults to 0x11, which is the typical value.
    static VIDEO_CH: Cell<u8> = Cell::new(0x11);
    // Current AA video focus state — updated from every VIDEO_FOCUS_NOTIFICATION.
    // Starts as Projected because AA always sends a PROJECTED notification at
    // session connect before any key events arrive.
    static FOCUS: Cell<FocusState> = Cell::new(FocusState::Projected);
    // Cooldown: time of the last VIDEO_FOCUS_REQUEST injection. We skip a new
    // injection if the previous one was < EXIT_COOLDOWN_MS milliseconds ago —
    // as a safeguard against accidental rapid consecutive presses.
    static LAST_INJECT_AT: Cell<Option<Instant>> = const { Cell::new(None) };
}

// Minimum interval between two consecutive VIDEO_FOCUS_REQUEST injections.
const EXIT_COOLDOWN_MS: u128 = 5_000;
// Upper bound on a plausible hold time. Instants are monotonic but may jump
// on some WASM runtimes if the underlying clock is not CLOCK_MONOTONIC.
// Any elapsed value above this is treated as a clock anomaly and ignored.
const MAX_HOLD_MS: u128 = 30_000;

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

// Parses the protobuf bytes of a VideoFocusNotification (payload[2..]) and
// returns the focus mode. Field 2 = VideoFocusMode (1=PROJECTED, 2=NATIVE).
fn parse_focus(data: &[u8]) -> Option<FocusState> {
    let mut pos = 0;
    while pos < data.len() {
        let tag = read_varint(data, &mut pos)?;
        let (field, wire) = ((tag >> 3) as u32, tag & 0x7);
        if field == 2 && wire == 0 {
            return match read_varint(data, &mut pos)? {
                1 => Some(FocusState::Projected),
                2 => Some(FocusState::Native),
                _ => None,
            };
        }
        skip_field(data, &mut pos, wire)?;
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
        // Sniff VIDEO_FOCUS_NOTIFICATION to learn the video channel and track
        // the current focus state. The first notification always arrives at AA
        // connect time (focus: PROJECTED) so both are set before key events land.
        if pkt.proxy_type == ProxyType::MobileDevice
            && pkt.message_id == MSG_VIDEO_FOCUS_NOTIFICATION
        {
            VIDEO_CH.with(|c| c.set(pkt.channel));
            if pkt.payload.len() >= 2 {
                if let Some(focus) = parse_focus(&pkt.payload[2..]) {
                    let prev = FOCUS.with(|f| f.get());
                    FOCUS.with(|f| f.set(focus));
                    if focus == FocusState::Native && prev == FocusState::Projected {
                        // A call started or the phone requested native focus while
                        // we might be mid-hold. Cancel so the button passes through
                        // freely for call management.
                        STATE.with(|s| s.set(PressState::Idle));
                        aa::packet::host::info("[aa-minimize] focus→NATIVE: cleared press state");
                    }
                }
            }
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

        // Don't intercept while AA is in the background or during a phone call.
        // In NATIVE focus, the PHONE button has call-management meaning — pass it through.
        if FOCUS.with(|f| f.get()) == FocusState::Native {
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

                    if elapsed_ms > MAX_HOLD_MS {
                        // Clock anomaly (e.g. WASM runtime using a non-monotonic
                        // clock that jumped on NTP sync). Treat as spurious.
                        aa::packet::host::info(&format!(
                            "[aa-minimize] ignoring {}ms hold (clock anomaly?)", elapsed_ms
                        ));
                        Decision::Drop
                    } else if elapsed_ms >= LONG_PRESS_MS {
                        // Long press: inject VIDEO_FOCUS_REQUEST directly via send()
                        // so no existing packet is corrupted (replace_current would
                        // blindly overwrite whatever came next in the HU→MD stream,
                        // including protocol-critical ACK or SSL packets).
                        let now = Instant::now();
                        let too_soon = LAST_INJECT_AT.with(|t| {
                            t.get()
                                .map(|last| now.duration_since(last).as_millis() < EXIT_COOLDOWN_MS)
                                .unwrap_or(false)
                        });
                        if too_soon {
                            aa::packet::host::info(&format!(
                                "[aa-minimize] long press {}ms → cooldown active, skipping",
                                elapsed_ms
                            ));
                        } else {
                            LAST_INJECT_AT.with(|t| t.set(Some(now)));
                            let ch = VIDEO_CH.with(|c| c.get());
                            aa::packet::host::info(&format!(
                                "[aa-minimize] long press {}ms → VIDEO_FOCUS_REQUEST on ch {:#04x}",
                                elapsed_ms, ch
                            ));
                            aa::packet::host::send(&Packet {
                                proxy_type: ProxyType::HeadUnit,
                                channel: ch,
                                packet_flags: PKT_FLAGS_SINGLE,
                                final_length: None,
                                message_id: MSG_VIDEO_FOCUS_REQUEST,
                                payload: VIDEO_FOCUS_NATIVE_PAYLOAD.to_vec(),
                            });
                        }
                        Decision::Drop
                    } else {
                        // Short press: we dropped every MD→HU down=true event while
                        // tracking the hold, so the HU never saw a key-down for this
                        // press — only its own ~20ms pulse, which isn't enough to
                        // trigger voice on its own. Re-inject a synthetic key-down to
                        // the HU, then forward this real key-up, reconstructing a
                        // minimal down/up pair at the HU.
                        aa::packet::host::info(&format!(
                            "[aa-minimize] short press {}ms → re-injecting key-down, forwarding key-up",
                            elapsed_ms
                        ));
                        aa::packet::host::send(&Packet {
                            proxy_type: ProxyType::MobileDevice,
                            channel: pkt.channel,
                            packet_flags: PKT_FLAGS_SINGLE,
                            final_length: None,
                            message_id: MSG_INPUT_REPORT,
                            payload: SHORT_PRESS_KEY_DOWN.to_vec(),
                        });
                        Decision::Forward
                    }
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
