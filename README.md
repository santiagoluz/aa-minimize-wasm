# aa-minimize-wasm

A [WASM hook script](https://github.com/aa-proxy/aa-proxy-rs) for `aa-proxy-rs` that intercepts a steering wheel button long-press and returns to the car's native screen without disconnecting Android Auto.

## How it works

Android Auto takes over the full screen, including the car's native bottom bar (AC, driving mode, etc.). This script lets you get back to the native UI without touching the phone — and without closing the AA session, so you can tap the AA icon on the native screen to resume instantly.

When you **long-press** the configured button:
1. The script detects the hold via repeated `down=true` events streamed by the phone (Phone → HU direction)
2. It drops those events while timing the hold with a monotonic clock
3. On release (≥ 500 ms), it injects a `VideoFocusRequestNotification { mode: NATIVE, reason: UNKNOWN }` (message id `0x8007`) via `send()` — a new packet added to the stream, without touching any existing packets
4. The phone receives the request, stops projecting video, keeps the TCP session alive (a steady ~85 B/s keepalive), and replies with `VideoFocusNotification { focus: NATIVE, unsolicited: true }` back to the HU
5. The HU switches to the native screen — session stays alive, and AA audio keeps playing

See [Reliability and limitations](#reliability-and-limitations) for when this can fail.

When you **short-press** the configured button:
1. The script tracks the hold the same way, but on release before the long-press threshold, it re-injects a synthetic key-down toward the phone (the original MD→HU down=true events were dropped while tracking the hold, so the phone never received the repeated key stream) and forwards the real key-up
2. This reconstructs a minimal key-down/key-up pair at the phone side, which is what triggers the Android Auto voice assistant action

The HU's own ~20ms key-down pulse alone is not sufficient to trigger the voice action — the phone needs to receive the complete key event to act on it.

**During a phone call**, the script detects that AA has released video focus (phone sends `VIDEO_FOCUS_NOTIFICATION(NATIVE)`) and stops intercepting the button entirely. Key events pass through unmodified so call-management actions (end call, etc.) work normally. Interception resumes when AA takes focus again (`VIDEO_FOCUS_PROJECTED`).

> **Why inject a request to the phone, not a notification to the HU?**
> Sending `VIDEO_FOCUS_NOTIFICATION(NATIVE)` (0x8008) directly to the HU causes it to drop the AA session, which then auto-reconnects. And sending `0x8008` to the *phone* also disconnects: the phone normally *sends* that message, not receives it, so it goes silent, and the proxy's stall detector kills the link after ~10–14 s of zero bytes.
> The working approach is to send a `VIDEO_FOCUS_REQUEST` (0x8007) *to the phone*: the phone stops projecting, keeps the TCP connection alive with keepalives, and notifies the HU itself — keeping both sides in sync and AA audio playing.
>
> Note: the car's *own* native takeovers (the app-drawer "Exit app" tile, the rear-camera view, a seat-belt popup) do **not** use `0x8007` at all — the phone emits an unsolicited `NATIVE` notification on its own, triggered by something outside the Android-Auto stream (hardware display switching). That path is not reproducible by injection; `0x8007` is the only injectable trigger that keeps audio.

> **Why Phone → HU direction for timing?**
> The HU always sends a brief ~20 ms pulse to the phone on key-down, regardless of how long
> you physically hold the button — so there is no hold-time information in the HeadUnit direction.
> The phone translates that pulse into a stream of repeated `down=true` events sent back to the HU
> every ~50 ms while the button is held, followed by a single `down=false` on release. That stream
> is what the script intercepts and times.

## Reliability and limitations

The long-press minimize works reliably in normal use, but it can occasionally fail — and when it does, the AA session drops and auto-reconnects after ~10–14 s. This is understood and is a phone-side limitation, not a bug in the script:

- **When it fails:** only under a heavy video stream (e.g. Waze zoomed right out with lots of moving map, plus music). Under that load the phone receives the `0x8007` request and stops projecting, but sometimes never completes the focus handshake — it sends no `NATIVE` notification back and starts no keepalive. Both traffic directions then fall to **0 bytes**, and the proxy's stall detector (`timeout_secs`, default 10) drops the link.
- **Why it can't be fixed here:** the request *is* delivered and acted on (video stops immediately), so it isn't packet loss or channel congestion — it's a race inside the phone while it is CPU-bound encoding video. `0x8007` is also protocol-bound to the video channel, so a different channel is not an option. Raising `timeout_secs` doesn't help either: the stream is genuinely frozen, so a longer timeout only delays the (recovering) reconnect.
- **What is unaffected:** whenever the phone *does* acknowledge (the common case), it settles into a steady ~85 B/s bidirectional keepalive and the minimized session survives indefinitely, with audio still playing.
- **Reliable fallback:** the head unit's own **MODE / audio-source button** always defocuses AA cleanly — but it switches audio to the radio (it drops AA audio), which is why this script exists for the audio-preserving case.

This was investigated at length by comparing captures of the script's injection against the car's native takeovers (MODE, rear camera, seat-belt popup) with full packet logging. The native takeovers keep audio *and* never fail, but they are phone-initiated with **no trigger anywhere in the Android-Auto stream** (all service kinds captured), so they cannot be reproduced by injection.

### State machine

The proxy sends each key event twice (once per direction). The script handles this with a simple state machine:

| State | Event | Result |
|-------|-------|--------|
| Idle | `down=true` | → Pressed, drop packet |
| Pressed | `down=true` | Stay Pressed, drop (proxy duplicate / key repeat) |
| Pressed, held ≥ 500 ms | `down=false` | → Handled, inject VIDEO_FOCUS_REQUEST via `send()` |
| Pressed, held < 500 ms | `down=false` | → Handled, re-inject key-down to phone, forward this key-up |
| Handled | `down=false` | → Idle, drop (proxy duplicate) |
| Any (FOCUS=Native) | any | → Forward immediately (call in progress, don't intercept) |

## Configuration

Open [`src/lib.rs`](src/lib.rs) and adjust these constants at the top:

```rust
// Steering wheel button to intercept (set to your car's keycode)
const KEYCODE_TRIGGER: u32 = 65540;

// How long the button must be held to trigger the long press action (milliseconds)
const LONG_PRESS_MS: u128 = 500;

// Minimum interval between consecutive VIDEO_FOCUS_REQUEST injections (milliseconds).
// Sending requests too quickly can disturb the AA session.
const EXIT_COOLDOWN_MS: u128 = 5_000;
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

### 4. Parse the log

Use [`aa-log-report.sh`](aa-log-report.sh) to produce a combined timeline of button presses, touch events, and video focus changes:

```bash
bash aa-log-report.sh aa-proxy-rs.log
```

Example output (button section relevant to keycode hunting):

```
2026-06-27, 01:14:30.790   [BTN]   keycode=84     short press  held=5ms
2026-06-27, 01:15:38.917   [BTN]   keycode=87     LONG  press  held=533ms
2026-06-27, 01:15:44.037   [BTN]   keycode=88     LONG  press  held=521ms
```

Set `KEYCODE_TRIGGER` in `src/lib.rs` to the keycode of the button you want to use.

## Log analysis

[`aa-log-report.sh`](aa-log-report.sh) generates a chronological timeline from an `aa-proxy-rs` log file, combining three event types:

| Tag | What it shows |
|-----|---------------|
| `[BTN]` | Button presses — keycode, short/LONG, hold duration |
| `[TOUCH]` | Touch events — 1/2-finger tap or swipe, coordinates, duration |
| `[FOCUS]` | Video focus changes — `VIDEO_FOCUS_REQUEST` (HU→phone) and `VIDEO_FOCUS_NOTIFICATION` (phone→HU) |

```bash
bash aa-log-report.sh aa-proxy-rs.log
```

Example output:

```
2026-06-30, 18:29:35.061   [TOUCH] 1-finger tap    x=41    y=404    156ms
2026-06-30, 18:29:39.315   [BTN]   keycode=65540  LONG  press  held=2389ms
2026-06-30, 18:30:41.505   [FOCUS] VIDEO_FOCUS_REQUEST → VIDEO_FOCUS_NATIVE (HU→phone)
2026-06-30, 18:30:41.526   [FOCUS] VIDEO_FOCUS_NOTIFICATION → VIDEO_FOCUS_NATIVE unsolicited (phone→HU)
2026-06-30, 18:31:03.729   [FOCUS] VIDEO_FOCUS_NOTIFICATION → VIDEO_FOCUS_PROJECTED unsolicited (phone→HU)
```

Useful for verifying that a long-press triggered the focus transition and confirming the session stayed alive (no unexpected reconnect after the `NATIVE` notification).

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
