# aa-minimize-wasm

A [WASM hook script](https://github.com/aa-proxy/aa-proxy-rs) for `aa-proxy-rs` that intercepts a steering wheel button long-press and returns to the car's native screen without disconnecting Android Auto.

## How it works

Android Auto takes over the full screen, including the car's native bottom bar (AC, driving mode, etc.). This script lets you get back to the native UI without touching the phone — and without closing the AA session, so you can tap the AA icon on the native screen to resume instantly.

When you **long-press** the configured button:
1. The script detects the hold via repeated `down=true` events streamed by the phone (Phone → HU direction)
2. It drops those events and sets a pending-exit flag
3. On the next packet flowing from the HU toward the phone, it uses `replace-current` to inject a `VideoFocusNotification { focus: NATIVE }` message
4. The phone receives the notification, gracefully stops projecting video, and sends `VideoFocusNotification { focus: NATIVE, unsolicited: true }` back to the HU
5. The HU switches to the native screen — session stays alive

**Short-press** still works normally — the HU's original key pulse reaches the phone unmodified.

> **Why inject to the phone, not the HU?**
> Sending `VIDEO_FOCUS_NATIVE` directly to the HU causes it to drop the AA session, which then auto-reconnects. The correct flow (mirroring what happens when you tap the native exit button) is to tell the *phone* to release focus. The phone then notifies the HU itself, keeping both sides in sync and the session alive.

> **Why Phone → HU direction for timing?**
> The HU always sends a brief ~20 ms pulse to the phone on key-down, regardless of how long
> you physically hold the button — so there is no hold-time information in the HeadUnit direction.
> The phone translates that pulse into a stream of repeated `down=true` events sent back to the HU
> every ~50 ms while the button is held, followed by a single `down=false` on release. That stream
> is what the script intercepts and times.

### State machine

The proxy sends each key event twice (once per direction). The script handles this with a simple state machine:

| State | Event | Result |
|-------|-------|--------|
| Idle | `down=true` | → Pressed, drop packet |
| Pressed | `down=true` | Stay Pressed, drop (proxy duplicate / key repeat) |
| Pressed, held ≥ 500 ms | `down=false` | → Handled, schedule exit (replace next HU→MD packet) |
| Pressed, held < 500 ms | `down=false` | → Handled, drop (short press — HU pulse already triggered the action) |
| Handled | `down=false` | → Idle, drop (proxy duplicate) |

## Configuration

Open [`src/lib.rs`](src/lib.rs) and adjust these constants at the top:

```rust
// Steering wheel button to intercept (set to your car's keycode)
const KEYCODE_TRIGGER: u32 = 65540;

// How long the button must be held to trigger the long press action (milliseconds)
const LONG_PRESS_MS: u128 = 500;
```

To intercept a different button, replace `65540` with the keycode your car sends for that button.
See [Finding your keycodes](#finding-your-keycodes) below.

### Common keycodes

| Value | Android constant | Typical button |
|-------|-----------------|----------------|
| 3 | `KEYCODE_HOME` | Home |
| 4 | `KEYCODE_BACK` | Back |
| 84 | `KEYCODE_SEARCH` | Voice / Mic |
| 87 | `KEYCODE_MEDIA_NEXT` | Next track |
| 88 | `KEYCODE_MEDIA_PREVIOUS` | Previous track |
| 126 | `KEYCODE_MEDIA_PLAY` | Play |
| 127 | `KEYCODE_MEDIA_PAUSE` | Pause |

Custom/vendor keycodes (e.g. `65540` / `0x10004`) may also appear depending on your head unit.

## Finding your keycodes

### 1. Enable packet debug logging

In the **aa-proxy-rs companion app** (or web UI at `http://10.0.0.1`), enable the following settings:

| Setting | Value |
|---------|-------|
| `pkt_debug` | `true` |
| `pkt_debug_filter_enabled` | `true` |
| `pkt_debug_filter_service_kinds` | `input` |
| `pkt_debug_filter_message_ids` | `0x8001` |
| `pkt_debug_filter_pretty_proto` | `true` |

This limits the log to input button events only, keeping the file small.

### 2. Press your buttons

Connect your phone and car as normal, then press the steering wheel buttons you want to identify.

### 3. Download the log

In the companion app or web UI (`http://10.0.0.1`), click **Download log**. You can also retrieve it via SSH:

```bash
scp -O root@10.0.0.1:/var/log/aa-proxy-rs.log ./aa-proxy-rs.log
```

### 4. Parse the log with awk

Show every button press with its timestamp, deduplicated (the proxy sends each event twice):

```bash
awk '
/^[0-9]{4}-[0-9]{2}-[0-9]{2}, [0-9]{2}:[0-9]{2}:[0-9]{2}/ { ts = substr($0, 1, 26) }
/key_event/ { in_key=1; kc=""; dn="" }
in_key && /keycode:/ { kc = $2 }
in_key && /down:/    { dn = $2; print ts, "keycode=" kc, "down=" dn; in_key=0 }
' aa-proxy-rs.log | awk '
{ key = $3 " " $4 }
key != prev { print; prev = key }
'
```

To also measure hold duration and flag long presses (≥ 500 ms):

```bash
awk '
function ts_to_ms(ts,    h, m, s) {
    h = substr(ts, 13, 2) + 0
    m = substr(ts, 16, 2) + 0
    s = substr(ts, 19) + 0
    return (h * 3600 + m * 60 + s) * 1000
}
/^[0-9]{4}-[0-9]{2}-[0-9]{2}, [0-9]{2}:[0-9]{2}:[0-9]{2}/ { ts = substr($0, 1, 26) }
/key_event/ { in_key=1; kc=""; dn="" }
in_key && /keycode:/ { kc = $2 }
in_key && /down:/    { dn = $2; in_key = 0
    if (dn == "true" && !(kc in down_ts)) {
        down_ts[kc] = ts_to_ms(ts)
        down_ts_str[kc] = ts
    } else if (dn == "false" && (kc in down_ts)) {
        dur = ts_to_ms(ts) - down_ts[kc]
        label = (dur >= 500) ? "LONG  press" : "short press"
        printf "%s  keycode=%-5s  %s  held=%dms\n", down_ts_str[kc], kc, label, dur
        delete down_ts[kc]
        delete down_ts_str[kc]
    }
}
' aa-proxy-rs.log
```

Example output:

```
2026-06-27, 01:14:30.790   keycode=84     short press  held=5ms
2026-06-27, 01:15:38.917   keycode=87     LONG  press  held=533ms
2026-06-27, 01:15:44.037   keycode=88     LONG  press  held=521ms
```

Set `KEYCODE_TRIGGER` in `src/lib.rs` to the keycode of the button you want to use.

## Build

> **Toolchain note:** `wit-bindgen` must be pinned to `=0.51.0` to match the `wasmtime 38`
> embedded in `aa-proxy-rs`. The `Cargo.toml` in this repo already has this pinned — do not
> upgrade it, or the generated WASM component format will be incompatible with the host runtime.

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Add the WASM component target
rustup target add wasm32-wasip2

# Build
cargo build --release --target wasm32-wasip2
```

Output: `target/wasm32-wasip2/release/aa_minimize_wasm.wasm`

## Deploy

Copy the `.wasm` file to `/data/wasm-hooks/` on the device. aa-proxy-rs watches that directory and hot-reloads scripts automatically — no restart needed.

```bash
scp -O target/wasm32-wasip2/release/aa_minimize_wasm.wasm root@10.0.0.1:/data/wasm-hooks/
ssh root@10.0.0.1 "sync && md5sum /data/wasm-hooks/aa_minimize_wasm.wasm"
```

Verify the md5 on the Pi matches the local file before testing:

```bash
md5sum target/wasm32-wasip2/release/aa_minimize_wasm.wasm
```

> **Important:** Always run `sync` on the Pi after uploading. The kernel's write-back cache
> means the file may not be fully written to the SD card yet. If the Pi loses power (ignition off)
> before the cache is flushed, the file will be corrupted. `sync` forces an immediate flush.

> **Note:** The device Wi-Fi (`aa-proxy` / `aa-proxy`) is used by the phone while Android Auto is running.
> To connect your laptop, temporarily disconnect the phone (enable airplane mode on the phone, then re-enable Wi-Fi only and connect manually to the car's Bluetooth for calls if needed).
> After uploading, reconnect the phone normally.

Confirm it loaded by checking the log for:
```
[wasm] loaded wasm script: /data/wasm-hooks/aa_minimize_wasm.wasm
[aa-minimize] loaded: long-press keycode 65540 → VIDEO_FOCUS_NATIVE
```
