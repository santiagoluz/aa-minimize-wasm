#!/usr/bin/env bash
# Usage: aa-log-report.sh <logfile>
# Produces a combined chronological timeline of button presses, touch events,
# and video focus changes from an aa-proxy-rs log file.

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <logfile>" >&2
    exit 1
fi

awk -v SWIPE_PX=75 '

function ts_ms(t,    a) {
    split(t, a, /[,. :]/)
    return (a[3]*3600 + a[4]*60 + a[5]) * 1000 + a[6]
}

/^[0-9]{4}-[0-9]{2}-[0-9]{2}, [0-9]{2}:[0-9]{2}:[0-9]{2}/ {
    ts = substr($0, 1, 26)
}

# ── Button presses ─────────────────────────────────────────────────────────────

/key_event/ { in_key=1; kc=""; dn="" }

in_key && /keycode:/ { kc = $2 }

in_key && /down:/ {
    dn = $2; in_key = 0
    if (dn == "true" && !(kc in btn_down_ms)) {
        btn_down_ms[kc]  = ts_ms(ts)
        btn_down_str[kc] = ts
    } else if (dn == "false" && (kc in btn_down_ms)) {
        dur   = ts_ms(ts) - btn_down_ms[kc]
        label = (dur >= 500) ? "LONG " : "short"
        printf "%s  [BTN]   keycode=%-5s  %s press  held=%dms\n",
               btn_down_str[kc], kc, label, dur
        delete btn_down_ms[kc]
        delete btn_down_str[kc]
    }
}

# ── Video focus events ─────────────────────────────────────────────────────────
# Each packet is logged twice by the proxy; suppress the duplicate within 200ms.

/message_id = 8007/ { in_vfr=1; vfr_mode="" }

in_vfr && /mode:/  { vfr_mode = $2 }
in_vfr && /^}$/ {
    in_vfr = 0
    if (vfr_mode != "") {
        key = "REQ_" vfr_mode
        now = ts_ms(ts)
        if (now - last_focus_ms[key] > 200) {
            printf "%s  [FOCUS] VIDEO_FOCUS_REQUEST → %s (HU→phone)\n", ts, vfr_mode
            last_focus_ms[key] = now
        }
        vfr_mode = ""
    }
}

/message_id = 8008/ { in_vfn=1; vfn_focus=""; vfn_unsol="" }

in_vfn && /focus:/      { vfn_focus = $2 }
in_vfn && /unsolicited/ { vfn_unsol = " unsolicited" }

in_vfn && /^}$/ {
    if (vfn_focus != "") {
        key = "NOTIF_" vfn_focus vfn_unsol
        now = ts_ms(ts)
        if (now - last_focus_ms[key] > 200) {
            printf "%s  [FOCUS] VIDEO_FOCUS_NOTIFICATION → %s%s (phone→HU)\n",
                   ts, vfn_focus, vfn_unsol
            last_focus_ms[key] = now
        }
        vfn_focus = ""; vfn_unsol = ""; in_vfn = 0
    }
}

# ── Touch events ───────────────────────────────────────────────────────────────

/message_id = 8001/ {
    in_input = 1; action = ""
    delete ptr_x; delete ptr_y
}

in_input && /touch_event/          { in_touch = 1 }
in_input && /pointer_data /        { in_ptr = 1; cur_x = ""; cur_y = ""; cur_id = 0 }
in_ptr   && /^      x: /          { cur_x  = $2 }
in_ptr   && /^      y: /          { cur_y  = $2 }
in_ptr   && /^      pointer_id: / { cur_id = $2 }
in_ptr   && /^    }$/ {
    ptr_x[cur_id] = cur_x
    ptr_y[cur_id] = cur_y
    in_ptr = 0
}

in_touch && !in_ptr && /^    action: / { action = $2 }

in_touch && /^}$/ {
    if (action == "ACTION_DOWN") {
        key0 = ptr_x[0] "," ptr_y[0]
        if (key0 != cur_touch_key) {
            cur_touch_key  = key0
            touch_down_str = ts
            touch_down_ms  = ts_ms(ts)
            touch_start_x  = ptr_x[0]; touch_start_y = ptr_y[0]
            touch_end_x    = ptr_x[0]; touch_end_y   = ptr_y[0]
            fingers = 1; moved = 0; emitted = 0
        }
    } else if (action == "ACTION_POINTER_DOWN") {
        if (fingers < 2) fingers = 2
    } else if (action == "ACTION_MOVED") {
        if (0 in ptr_x) {
            touch_end_x = ptr_x[0]; touch_end_y = ptr_y[0]
            dx = touch_end_x - touch_start_x; if (dx < 0) dx = -dx
            dy = touch_end_y - touch_start_y; if (dy < 0) dy = -dy
            if (dx > SWIPE_PX || dy > SWIPE_PX) moved = 1
        }
    } else if (action == "ACTION_UP" && !emitted && touch_down_ms > 0) {
        if (0 in ptr_x) { touch_end_x = ptr_x[0]; touch_end_y = ptr_y[0] }
        dur = ts_ms(ts) - touch_down_ms
        if (dur < 0) dur += 3600000
        fl = (fingers >= 2) ? "2-finger" : "1-finger"
        if (!moved)
            printf "%s  [TOUCH] %s tap    x=%-5s y=%-5s  %dms\n",
                   touch_down_str, fl, touch_start_x, touch_start_y, dur
        else
            printf "%s  [TOUCH] %s swipe  (%s,%s)→(%s,%s)  %dms\n",
                   touch_down_str, fl, touch_start_x, touch_start_y,
                   touch_end_x, touch_end_y, dur
        emitted = 1
    }
    action = ""; in_touch = 0
}

/^}$/ && in_input { in_input = 0 }

' "$1"
