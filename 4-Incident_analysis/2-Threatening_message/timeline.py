#!/usr/bin/env python3
import argparse
import json
import os
import re
from pathlib import Path
from datetime import datetime, timezone

DEFAULT_YEAR_FOR_ZERO = 2025
OUT_PATH = "timeline.txt"

TIME_FIELDS_PRIORITY = [
    "last_written_time",  # syslog
    "recorded_time",      # apache access
    "creation_time",      # bodyfile
    "modification_time",
    "change_time",
    "access_time",
]

NUMERIC_NAME_RE = re.compile(r"^(\d+)(?:\.json)?$")

def fmt2(n: int) -> str:
    return f"{int(n):02d}"

def parse_timeelements(obj: dict) -> str | None:
    tet = obj.get("time_elements_tuple")
    if not isinstance(tet, list) or len(tet) < 6:
        return None
    year, month, day, hour, minute, second = tet[:6]
    micro = tet[6] if len(tet) >= 7 else 0
    if year == 0:
        year = DEFAULT_YEAR_FOR_ZERO
    y = f"{int(year):04d}"
    m = fmt2(month); d = fmt2(day)
    H = fmt2(hour);  M = fmt2(minute); S = fmt2(second)
    us = f"{int(micro):06d}"
    return f"{y}{m}{d}-{H}{M}{S}.{us}"

def parse_posix_time(obj: dict) -> str | None:
    ts = obj.get("timestamp")
    if ts is None:
        return None
    try:
        dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
    except Exception:
        return None
    return dt.strftime("%Y%m%d-%H%M%S.") + f"{dt.microsecond:06d}"

def extract_timestamp_str(rec: dict) -> str | None:
    # 1) preferované polia
    for key in TIME_FIELDS_PRIORITY:
        t = rec.get(key)
        if isinstance(t, dict) and t.get("__type__") == "DateTimeValues":
            cls = t.get("__class_name__", "")
            if "TimeElements" in cls:
                s = parse_timeelements(t)
                if s: return s
            elif cls == "PosixTime":
                s = parse_posix_time(t)
                if s: return s
    # 2) fallback: globálne prehľadanie všetkých vnorení
    stack = [rec]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if node.get("__type__") == "DateTimeValues":
                cls = node.get("__class_name__", "")
                if "TimeElements" in cls:
                    s = parse_timeelements(node)
                    if s: return s
                elif cls == "PosixTime":
                    s = parse_posix_time(node)
                    if s: return s
            for v in node.values():
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(node, list):
            for v in node:
                if isinstance(v, (dict, list)):
                    stack.append(v)
    return None

def extract_message(rec: dict) -> str | None:
    # 1) syslog/nfdump
    body = rec.get("body")
    if isinstance(body, str) and body.strip():
        return body.strip()
    # 2) apache access
    if "http_request" in rec:
        ua = rec.get("http_request_user_agent", "")
        bytes_ = rec.get("http_response_bytes", "")
        code = rec.get("http_response_code", "")
        ip = rec.get("ip_address", "")
        parts = [
            str(rec.get("http_request", "")).strip(),
            str(ua).strip(),
            f"bytes={bytes_}".strip(),
            f"code={code}".strip(),
            str(ip).strip(),
        ]
        return " ".join(p for p in parts if p)
    # 3) fs:bodyfile:entry – urob krátky sumár (ak chceš)
    if rec.get("data_type", "").startswith("fs:bodyfile:entry"):
        fn = rec.get("filename", "")
        size = rec.get("size", "")
        md5 = rec.get("md5", "")
        mode = rec.get("mode_as_string", "")
        extras = []
        if size != "": extras.append(f"size={size}")
        if md5: extras.append(f"md5={md5}")
        if mode: extras.append(mode)
        tail = " ".join(extras)
        return f"{fn} {tail}".strip()
    return None

def iter_blob_files(blobs_dir: Path):
    # prejde všetky súbory v adresári (bez rekurzie),
    # vyberie tie, ktorých názov je číslo s voliteľnou príponou .json
    for entry in os.scandir(blobs_dir):
        if not entry.is_file():
            continue
        m = NUMERIC_NAME_RE.match(entry.name)
        if not m:
            continue
        event_id = int(m.group(1))
        yield event_id, Path(entry.path)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--blobs", default="blobs", help="Priečinok so JSON súbormi (1.json …)")
    ap.add_argument("--out", default=OUT_PATH, help="Výstupný súbor timeline")
    args = ap.parse_args()

    blobs_dir = Path(args.blobs)
    out_path = Path(args.out)

    if not blobs_dir.exists():
        print(f"[!] Neexistuje priečinok: {blobs_dir.resolve()}")
        return

    items = []  # (timestamp_str, event_id, line)
    scanned = 0
    parsed = 0
    skipped_no_ts = 0
    skipped_no_msg = 0
    json_err = 0

    # iteruj súbory podľa event_id vzostupne (stabilné triedenie v rámci rovnakého času)
    for event_id, p in sorted(iter_blob_files(blobs_dir), key=lambda t: t[0]):
        if event_id < 53491:
            continue
        scanned += 1
        try:
            txt = p.read_text(encoding="utf-8", errors="ignore")
            rec = json.loads(txt)
        except Exception:
            json_err += 1
            continue

        ts = extract_timestamp_str(rec)
        if not ts:
            skipped_no_ts += 1
            continue

        msg = extract_message(rec)
        if not msg:
            skipped_no_msg += 1
            continue

        items.append((ts, event_id, f"{ts} {event_id} {msg}"))
        parsed += 1
        if parsed % 5000 == 0:
            print(f"  … spracovaných {parsed}/{scanned}")

    # zoradenie: primárne čas, sekundárne event_id
    items.sort(key=lambda t: (t[0], t[1]))

    with out_path.open("w", encoding="utf-8") as f:
        for _, __, line in items:
            f.write(line + "\n")

    print(f"[+] Hotovo: {out_path}  (riadkov: {len(items)})")
    print(f"    Súbory: scanned={scanned}, parsed={parsed}, json_err={json_err}, no_ts={skipped_no_ts}, no_msg={skipped_no_msg}")

if __name__ == "__main__":
    main()
