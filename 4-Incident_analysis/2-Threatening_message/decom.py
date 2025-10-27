#!/usr/bin/env python3
"""
decompress_plaso_event_data.py

Prečíta event_data._identifier a event_data._data z image.plaso (SQLite),
dekomprimuje _data (zlib) a uloží výsledok do priečinka "blobs" ako "<_identifier>.json".

- Ak dekompresia prebehne a obsah je platné JSON -> uloží pekne formátované JSON.
- Ak dekompresia prebehne, ale obsah nie je JSON -> uloží JSON s base64 obsahu a preview textom.
- Ak dekompresia zlyhá -> uloží JSON s popisom chyby a base64 blobom.

Nezabudni: máš tu stovky tisíc záznamov -> script beží sekvenčne, priečinok blobs sa vytvorí ak neexistuje.
"""
import sqlite3
import zlib
import json
import os
import base64
import sys
import time
from pathlib import Path

DB_PATH = "image.plaso"   # uprav podľa potreby
OUT_DIR = "blobs"
PROGRESS_INTERVAL = 1000  # vypíše riadok každých N záznamov

def ensure_outdir(path):
    Path(path).mkdir(parents=True, exist_ok=True)

def process_row(identifier, blob):
    result = None
    try:
        # blob je surové bytes z DB - dekomprimovať
        decompressed = zlib.decompress(blob)
    except Exception as e:
        # dekompresia zlyhala - uložíme chybu a base64 blob
        return {
            "_identifier": identifier,
            "_status": "decompression_error",
            "error": str(e)
            # nepridávame tu celý hex aby súbory neboli príliš veľké; ak chceš,
            # môžeš pridať base64 zakódovaný blob:
            , "blob_base64": base64.b64encode(blob).decode("ascii")
        }

    # pokúsime sa parsovať JSON
    try:
        parsed = json.loads(decompressed.decode("utf-8", errors="strict"))
        # ak úspech -> vrátime parsed objekt (bude uložený pekne)
        return {
            "_identifier": identifier,
            "_status": "ok",
            "_parsed_json": parsed
        }
    except Exception:
        # nie je to platné JSON; uložíme base64 a preview text (bez poškodzovania)
        preview_text = ""
        try:
            preview_text = decompressed[:1000].decode("utf-8", errors="ignore")
        except Exception:
            preview_text = ""
        return {
            "_identifier": identifier,
            "_status": "decompressed_not_json",
            "raw_base64": base64.b64encode(decompressed).decode("ascii"),
            "raw_preview": preview_text
        }

def safe_write_json(path, obj):
    # atomické zápisy: najprv do .tmp potom rename
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
    os.replace(tmp_path, path)

def main():
    ensure_outdir(OUT_DIR)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = None
    cur = conn.cursor()

    # COUNT pre jednoduchú spätnú väzbu (môže byť pomalé, ale užitočné)
    try:
        total = cur.execute("SELECT COUNT(*) FROM event_data").fetchone()[0]
    except Exception:
        total = None

    print(f"Opened DB: {DB_PATH}")
    if total is not None:
        print(f"Total event_data rows: {total}")
    print(f"Output directory: {OUT_DIR}")
    print("Starting scan...")

    start = time.time()
    processed = 0
    success = 0
    decomp_err = 0
    notjson = 0

    # iterate cursor to avoid načítavanie všetkých do pamäte
    for row in cur.execute("SELECT _identifier, _data FROM event_data"):
        identifier, blob = row[0], row[1]
        try:
            out = process_row(identifier, blob)
        except Exception as e:
            out = {"_identifier": identifier, "_status": "processing_error", "error": str(e)}

        # If out contains _parsed_json key and status ok, we prefer to save the parsed content directly
        out_path = os.path.join(OUT_DIR, f"{identifier}.json")

        # If parsed JSON present, unwrap it so file contains the original data instead of wrapper
        if out.get("_status") == "ok" and "_parsed_json" in out:
            try:
                # write the parsed JSON directly (pretty)
                safe_write_json(out_path, out["_parsed_json"])
                success += 1
            except Exception as e:
                # fallback to wrapper
                out["_write_error"] = str(e)
                safe_write_json(out_path, out)
        else:
            # write wrapper object (contains status, base64, preview, or error)
            safe_write_json(out_path, out)
            if out.get("_status") == "decompression_error":
                decomp_err += 1
            elif out.get("_status") == "decompressed_not_json":
                notjson += 1

        processed += 1
        if processed % PROGRESS_INTERVAL == 0:
            elapsed = time.time() - start
            pct = f"{processed}/{total}" if total else f"{processed}"
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Processed {pct} rows, elapsed {elapsed:.0f}s")

    conn.close()
    elapsed = time.time() - start
    print("="*40)
    print(f"Done. Processed: {processed} rows in {elapsed:.0f}s")
    print(f" - parsed-as-json files: {success}")
    print(f" - decompression errors: {decomp_err}")
    print(f" - decompressed but not-json: {notjson}")
    print(f"Files are in: {os.path.abspath(OUT_DIR)}")

if __name__ == "__main__":
    # možeš si upravit DB_PATH/OUT_DIR tu alebo nastavit cez argumenty (nie je implementované)
    if not os.path.exists(DB_PATH):
        print(f"ERROR: DB not found at {DB_PATH}", file=sys.stderr)
        sys.exit(1)
    main()
