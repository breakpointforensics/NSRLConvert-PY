import sqlite3
import time
import sys
import threading
import ujson
import os
import re
import logging
from datetime import datetime

# Author: David Haddad
# Breakpoint Forensics
# Credit to Chris Lees for original research and C-based tool @ https://askclees.com/2023/04/05/importing-nsrl-v3-hashsets-into-legacy-tools/
# Script: NSRLConvert-PY.py
# Date: 01-09-2026
INTERNAL_BUILD_VERSION = "1.4.7"
PUBLIC_BUILD_VERSION = "1.3"

# SQLite PRAGMA statements to optimize performance
pragma = [
    "pragma journal_mode = WAL;",      # Use Write-Ahead Logging for better concurrency
    "pragma synchronous = normal;",    # Balance between safety and performance
    "pragma temp_store = memory;",     # Store temporary tables in memory to speed up processing
    "pragma mmap_size = 30000000000;"  # Set memory-mapped I/O to 30GB
]

# ---------------------------
# Logging
# ---------------------------
def get_log_dir():
    """
    "Same folder as utility" = folder containing this script, when possible.
    Falls back to current working directory.
    """
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except Exception:
        return os.getcwd()

def setup_logger():
    log_dir = get_log_dir()
    os.makedirs(log_dir, exist_ok=True)

    log_name = f"NSRLConvert_{datetime.now().strftime('%Y%m%d')}.log"
    log_path = os.path.join(log_dir, log_name)

    logger = logging.getLogger("NSRLConvert")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    logger.info(f"Logging to: {log_path}")
    logger.info(f"Breakpoint NSRL Converter | Public {PUBLIC_BUILD_VERSION} | Internal {INTERNAL_BUILD_VERSION}")
    
    return logger

LOGGER = setup_logger()

def log(msg, level="info"):
    # keep console output + also log to file
    if level == "error":
        LOGGER.error(msg)
    elif level == "warning":
        LOGGER.warning(msg)
    else:
        LOGGER.info(msg)

# ---------------------------
# Helpers (timing, pragma)
# ---------------------------
def print_time(message):
    """Prints the current time with a custom message."""
    now = time.localtime()
    log(f"{message} {time.strftime('%Y-%m-%d %H:%M:%S', now)}")

def set_pragma(db):
    """Applies PRAGMA settings to optimize database performance (best-effort)."""
    cursor = db.cursor()
    for p in pragma:
        try:
            cursor.execute(p)
        except Exception as e:
            log(f"PRAGMA failed ({p}): {e}", "warning")
    cursor.close()

def print_usage():
    """Displays usage instructions for the script."""
    log("Usage:")
    log("\npython script.py [input source] [output file] [hash_type] [output_format] [--dedup]")
    log("input source can be an NSRL .db (SQLite) OR an NSRL delta .sql file.")
    log("hash_type is optional, can be 'md5' (default) or 'sha1'.")
    log("output_format is optional, can be 'text' (default) or 'json'(ProjectVIC).")
    log(
    "--dedup is optional: Forces deduplication on FULL NSRL .db files only. "
    "Minimal .db and delta .sql sources are always deduplicated."
    )
    log("\nIf run with no CLI arguments, the GUI will launch.")

# ---------------------------
# Progress meters
# ---------------------------
def progress_meter(total_rows, processed_rows, label="hashes"):
    """Displays a progress meter that updates every 5 seconds.

    processed_rows is [count, done_flag]
    - total_rows may be an estimate
    - Percent is capped at 99.9% until completion
    - label controls the displayed unit (e.g., hashes, lines)
    """
    last_reported = 0
    while True:
        count = processed_rows[0]
        done = processed_rows[1]

        if count > last_reported:
            if total_rows:
                raw_pct = (count / total_rows) * 100
                pct = min(raw_pct, 99.9)
                log(f"Processed {count} out of {total_rows} {label} ({pct:.2f}%)")
            else:
                log(f"Processed {count} {label}...")
            last_reported = count

        if done:
            break

        time.sleep(5)

    # Always end with a clear 100% completion line
    if label == "hashes":
        log(f"Processing complete: {processed_rows[0]} hashes exported (100.00%)")
    else:
        log(f"Processing complete: {processed_rows[0]} {label} processed (100.00%)")

def progress_meter_unknown(processed_rows, label="hashes"):
    """
    Progress meter when total is unknown.
    processed_rows = [count, done_flag]
    """
    last_reported = 0
    while not processed_rows[1]:
        if processed_rows[0] > last_reported:
            log(f"Processed {processed_rows[0]} {label}...")
            last_reported = processed_rows[0]
        time.sleep(5)
    if label == "hashes":
        log(f"Processing complete: {processed_rows[0]} hashes exported.")
    else:
        log(f"Processing complete: {processed_rows[0]} {label}.")

# ---------------------------
# Source detection / resolution
# ---------------------------
def is_sqlite_file(path):
    """Detection: SQLite header."""
    try:
        with open(path, "rb") as f:
            header = f.read(16)
        return header.startswith(b"SQLite format 3\x00")
    except OSError:
        return False

def resolve_input_source(input_path):
    """
    Handle common user mistakes:
      - They pick schema.sql instead of the .db (full release)
      - They pick schema.sql instead of *_delta.sql (delta release)
    """
    p = os.path.abspath(input_path)
    folder = os.path.dirname(p)
    base = os.path.basename(p)
    lower = base.lower()

    if lower.endswith(".db") and os.path.exists(p):
        return p

    if not lower.endswith(".sql"):
        return p

    if "delta" in lower:
        return p

    looks_like_schema = ("schema" in lower)
    if looks_like_schema:
        candidate_db = re.sub(r'(\.schema|_schema|-schema)\.sql$', '.db', base, flags=re.IGNORECASE)
        candidate_db_path = os.path.join(folder, candidate_db)
        if os.path.exists(candidate_db_path) and os.path.isfile(candidate_db_path):
            log(f"Schema SQL provided; using sibling DB: {candidate_db_path}")
            return candidate_db_path

        stem = re.sub(r'(\.schema|_schema|-schema)(?=\.sql$)', '', base, flags=re.IGNORECASE)
        alt_db = stem.replace(".sql", ".db")
        alt_db_path = os.path.join(folder, alt_db)
        if os.path.exists(alt_db_path) and os.path.isfile(alt_db_path):
            log(f"Schema SQL provided; using sibling DB: {alt_db_path}")
            return alt_db_path

        candidates = []
        candidates.append(stem.replace(".sql", "_delta.sql"))
        candidates.append(stem.replace(".sql", ".delta.sql"))
        candidates.append(stem.replace(".sql", "-delta.sql"))
        candidates.append(re.sub(r'schema', 'delta', base, flags=re.IGNORECASE))

        seen = set()
        for c in candidates:
            if c in seen:
                continue
            seen.add(c)
            candidate_path = os.path.join(folder, c)
            if os.path.exists(candidate_path) and os.path.isfile(candidate_path):
                log(f"Schema SQL provided; using sibling delta SQL: {candidate_path}")
                return candidate_path

        return None

    return p

# ---------------------------
# Progress estimation (no COUNT)
# ---------------------------
CAL_DB_SIZE_GB = 32.0
CAL_FILE_ROWS = 79771758
CAL_DISTINCT_RATIO = 29072853 / 79771758  # ~0.3645

def estimate_total_rows_from_filesize(db_path, is_minimal):
    try:
        size_bytes = os.path.getsize(db_path)
        size_gb = size_bytes / (1024 ** 3)
        rows_per_gb = CAL_FILE_ROWS / CAL_DB_SIZE_GB if CAL_DB_SIZE_GB else 0
        est_file_rows = int(rows_per_gb * size_gb) if rows_per_gb else 0

        if is_minimal:
            est = int(est_file_rows * CAL_DISTINCT_RATIO)
        else:
            est = est_file_rows

        est = int(est * 1.10)  # 10% buffer
        return max(est, 1), size_gb
    except Exception:
        return 1, None

# ---------------------------
# DB view selection
# ---------------------------
def get_view_name(cursor):
    cursor.execute("SELECT name FROM sqlite_master WHERE type='view';")
    views = [row[0] for row in cursor.fetchall()]

    if 'DISTINCT_HASH' in views:
        log('NSRL DB Style Detected: Minimal')
        return 'DISTINCT_HASH'
    elif 'FILE' in views:
        log('NSRL DB Style Detected: Full')
        return 'FILE'
    else:
        raise ValueError("Neither 'DISTINCT_HASH' nor 'FILE' view found in the database.")


def get_hash_column_name_from_view(cursor, view_name, hash_column_index):
    """
    Determine the actual column name for the selected hash column by inspecting cursor.description.
    Avoids hard-coding md5/sha1 casing across NSRL DB variants.
    """
    cursor.execute(f"SELECT * FROM {view_name} LIMIT 1;")
    desc = cursor.description or []
    if not desc or hash_column_index >= len(desc):
        raise ValueError("Unable to determine hash column name for dedup query.")
    return desc[hash_column_index][0]

# ---------------------------
# SQL delta parsing
# ---------------------------
def split_sql_csv_values(values_text):
    out = []
    i = 0
    n = len(values_text)
    while i < n:
        while i < n and values_text[i] in " \t\r\n,":
            i += 1
        if i >= n:
            break

        if values_text[i] == "'":
            i += 1
            buf = []
            while i < n:
                c = values_text[i]
                if c == "'":
                    if i + 1 < n and values_text[i + 1] == "'":
                        buf.append("'")
                        i += 2
                        continue
                    i += 1
                    break
                buf.append(c)
                i += 1
            out.append("".join(buf))
        else:
            start = i
            while i < n and values_text[i] not in ",\r\n":
                i += 1
            token = values_text[start:i].strip()
            out.append(token)

    return out

def fast_line_count(path):
    total = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            total += chunk.count(b"\n")
    return total

def parse_insert_into_hash_line(line):
    """
    Parse one INSERT line for NSRL delta packages.

    Minimal delta example:
      INSERT INTO FILE(sha256,sha1,md5,...) VALUES('..','..','..',...);

    Full delta example:
      INSERT INTO METADATA(...,crc32,md5,sha1,sha256) VALUES(...,'..','..','..','..');

    Returns dict {column: value} (lowercased column names) or None if not a supported insert.
    """
    # Fast pre-filter (case-insensitive) to avoid parsing every line
    l = line.lower()
    if "insert into" not in l:
        return None
    if "insert into file" not in l and "insert into metadata" not in l:
        return None

    try:
        before_vals, vals_part = line.split("VALUES", 1)

        # Find the table name between "INSERT INTO" and the first "("
        m = re.search(r'insert\s+into\s+([A-Za-z0-9_]+)\s*\(', before_vals, flags=re.IGNORECASE)
        if not m:
            return None
        table = m.group(1).strip().lower()
        if table not in ("file", "metadata"):
            return None

        # Column list is inside the first (...) after table name
        cols_start = before_vals.index("(", m.end(1))
        cols_end = before_vals.index(")", cols_start)
        cols_text = before_vals[cols_start + 1:cols_end]
        cols = [c.strip().strip('"').strip('`') for c in cols_text.split(",")]

        # VALUES list is inside the last (...) in vals_part
        vals_start = vals_part.index("(") + 1
        vals_end = vals_part.rindex(")")
        vals_text = vals_part[vals_start:vals_end]

        values = split_sql_csv_values(vals_text)
        if len(values) != len(cols):
            return None

        return dict(zip([c.lower() for c in cols], values))
    except Exception:
        return None


def process_sql_delta(input_path, output_path, hash_type, output_format, hash_key):
    log("NSRL Source Detected: SQL (.sql)")

    try:
        total_lines = fast_line_count(input_path)
    except Exception as e:
        total_lines = 0
        log(f"Could not pre-count lines (continuing without percent): {e}", "warning")

    extracted_count = 0
    deduped_count = 0
    seen_hashes = set()

    processed_rows = [0, False]
    if total_lines > 0:
        log(f"Estimated progress total from file line count: {total_lines} lines (estimated)")
        progress_thread = threading.Thread(target=progress_meter, args=(total_lines, processed_rows, "lines"))
    else:
        log("Progress total unknown; showing processed line count only.")
        progress_thread = threading.Thread(target=progress_meter_unknown, args=(processed_rows, "lines"))
    progress_thread.start()

    results = None
    media_id = 1
    if output_format == 'json':
        results = {
            "@odata.context": "http://github.com/VICSDATAMODEL/ProjectVic/DataModels/2.0.xml/Default/$metadata#Media",
            "value": []
        }

    with open(input_path, "r", encoding="utf-8", errors="replace") as f_in, open(output_path, "w", encoding="utf-8") as f_out:
        for line in f_in:
            processed_rows[0] += 1

            line = line.strip()
            if not line or not line.startswith("INSERT INTO"):
                continue

            row_map = parse_insert_into_hash_line(line)
            if not row_map:
                continue

            hash_value = row_map.get(hash_type)
            if not hash_value:
                continue

            extracted_count += 1

            if hash_value in seen_hashes:
                continue

            seen_hashes.add(hash_value)
            deduped_count += 1

            if output_format == 'text':
                f_out.write(hash_value + "\n")
            else:
                results["value"].append({
                    "MediaID": media_id,
                    "Category": 0,
                    hash_key: hash_value
                })
                media_id += 1

        if output_format == 'json':
            log("Writing JSON to Disk")
            ujson.dump(results, f_out, indent=4, escape_forward_slashes=False)

    processed_rows[1] = True
    progress_thread.join()

    log(f"Delta extraction complete. Total hash rows encountered: {extracted_count}")
    log(f"Delta extraction complete. Unique hashes written: {deduped_count}")

    return {"mode": "delta", "encountered": extracted_count, "unique": deduped_count}

# ---------------------------
# Core conversion wrapper (used by CLI + GUI)
# ---------------------------
def convert_nsrl(input_path, output_path, hash_type="md5", output_format="text", dedup=False):
    hash_type = (hash_type or "md5").lower()
    output_format = (output_format or "text").lower()

    if hash_type not in ("md5", "sha1"):
        raise ValueError("hash_type must be 'md5' or 'sha1'")
    if output_format not in ("text", "json"):
        raise ValueError("output_format must be 'text' or 'json'")

    hash_column = 2 if hash_type == 'md5' else 1
    hash_key = hash_type.upper()

    resolved = resolve_input_source(input_path)
    if resolved is None:
        raise FileNotFoundError("Schema SQL provided but matching .db or *_delta.sql could not be found in the same folder.")
    input_path = resolved

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input path does not exist: {input_path}")

    if not is_sqlite_file(input_path):
        return process_sql_delta(input_path, output_path, hash_type, output_format, hash_key)

    log("NSRL Source Detected: SQLite DB (.db)")
    try:
        db = sqlite3.connect(input_path, uri=True)
        log("Opened database successfully")
    except sqlite3.Error as e:
        raise RuntimeError(f"Can't open database: {e}") from e

    set_pragma(db)
    cursor = None

    try:
        cursor = db.cursor()
        view_name = get_view_name(cursor)

        log('Parsing Database. This can take a few minutes.')

        is_minimal = (view_name == 'DISTINCT_HASH')
        total_rows, size_gb = estimate_total_rows_from_filesize(input_path, is_minimal=is_minimal)
        if size_gb is not None:
            log(f"Estimated progress total based on file size ({size_gb:.2f} GB): {total_rows} hashes (estimated)")
        else:
            log(f"Estimated progress total: {total_rows} hashes (estimated)")

        processed_rows = [0, False]
        progress_thread = threading.Thread(target=progress_meter, args=(total_rows, processed_rows, "hashes"))
        progress_thread.start()

        chunk_size = 10000000
        # Select rows to export
        if dedup and view_name == "FILE":
            # Use SQLite DISTINCT for full DB to avoid massive in-memory sets.
            hash_col_name = get_hash_column_name_from_view(cursor, view_name, hash_column)
            log(f"Full DB dedup enabled; exporting DISTINCT {hash_col_name} values from FILE")
            cursor.execute(f'SELECT DISTINCT "{hash_col_name}" FROM {view_name};')
            dedup_select_single_col = True
        else:
            cursor.execute(f"SELECT * from {view_name};")
            dedup_select_single_col = False


        results = None
        media_id = 1
        if output_format == 'json':
            results = {
                "@odata.context": "http://github.com/VICSDATAMODEL/ProjectVic/DataModels/2.0.xml/Default/$metadata#Media",
                "value": []
            }

        with open(output_path, "w", encoding="utf-8") as output_file:
            while True:
                rows = cursor.fetchmany(chunk_size)
                if not rows:
                    break
                for row in rows:
                    hash_value = row[0] if dedup_select_single_col else row[hash_column]
                    if output_format == 'text':
                        output_file.write(hash_value + "\n")
                    else:
                        results["value"].append({
                            "MediaID": media_id,
                            "Category": 0,
                            hash_key: hash_value
                        })
                        media_id += 1
                    processed_rows[0] += 1

            if output_format == 'json':
                log('Writing JSON to Disk')
                ujson.dump(results, output_file, indent=4, escape_forward_slashes=False)

        processed_rows[1] = True
        progress_thread.join()

        return {"mode": "db", "exported": processed_rows[0], "view": view_name}
    finally:
        try:
            if cursor:
                cursor.close()
        except Exception:
            pass
        try:
            db.close()
        except Exception:
            pass

# ---------------------------
# GUI
# ---------------------------
def _ensure_output_extension(output_path, output_format):
    ext = ".json" if output_format == "json" else ".txt"
    if not output_path.lower().endswith(ext):
        return output_path + ext
    return output_path

def run_gui():
    # Lazy import so CLI users don't need FreeSimpleGUI installed
    import FreeSimpleGUI as sg

    sg.theme("SystemDefault")
    windowicon = b'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'
    

    file_types = (("NSRL DB/SQL", "*.db *.sql"),)
    layout = [
        [sg.Text("Breakpoint NSRL Converter", font=("Segoe UI", 14, "bold"))],
        [sg.Text("Input (.db or .sql):", size=(16, 1)),
         sg.Input(key="input_path", enable_events=True, expand_x=True),
         sg.FileBrowse(file_types=file_types)],
        [sg.Text("Output folder:", size=(16, 1)),
         sg.Input(key="out_folder", enable_events=True, expand_x=True),
         sg.FolderBrowse()],
        [sg.Text("Output filename:", size=(16, 1)),
         sg.Input("NSRL_Hashes", key="out_name", enable_events=True, expand_x=True),
         sg.Text("", size=(6,1), key="ext_label")],
        [sg.Text("Hash type:", size=(16, 1)),
         sg.Combo(values=["md5", "sha1"], default_value="md5", key="hash_type", readonly=True, enable_events=True),
         sg.Text("Output format:", pad=((20,0),(0,0))),
         sg.Combo(values=["text", "json"], default_value="text", key="output_format", readonly=True, enable_events=True)],
        [sg.Checkbox("Deduplicate (Full DB only)", default=True, key="dedup")],
        [sg.HorizontalSeparator()],
        [sg.Button("Convert", key="convert", disabled=True),
         sg.Button("Exit")],
        [sg.Output(size=(100, 16), key="status")]
    ]

    window = sg.Window("Breakpoint NSRL Converter", layout, icon=windowicon, finalize=True)

    # Ensure logger StreamHandler writes to the redirected stdout used by sg.Output
    # (Logger is created at import time, so we rebind after the GUI is finalized.)
    for h in LOGGER.handlers:
        if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
            h.stream = sys.stdout

    def update_ext_label():
        fmt = window["output_format"].get() or "text"
        window["ext_label"].update(".json" if fmt == "json" else ".txt")

    def can_convert(values):
        inp = (values.get("input_path") or "").strip().strip('"')
        out_folder = (values.get("out_folder") or "").strip().strip('"')
        out_name = (values.get("out_name") or "").strip()
        if not inp or not os.path.isfile(inp):
            return False
        if not out_folder or not os.path.isdir(out_folder):
            return False
        if not out_name:
            return False
        if not (inp.lower().endswith(".db") or inp.lower().endswith(".sql")):
            return False
        return True

    update_ext_label()
    converting = False

    while True:
        event, values = window.read(timeout=250)

        if event in (sg.WINDOW_CLOSED, "Exit"):
            break

        if event == "output_format":
            update_ext_label()

        if not converting:
            window["convert"].update(disabled=not can_convert(values))

        if event == "convert":
            inp = values["input_path"].strip().strip('"')
            out_folder = values["out_folder"].strip().strip('"')
            out_name = values["out_name"].strip()
            hash_type = values["hash_type"]
            out_fmt = values["output_format"]
            dedup = bool(values.get("dedup"))

            if not can_convert(values):
                sg.popup_error("Please select a valid input file, output folder, and output filename.")
                continue

            out_path = os.path.join(out_folder, out_name)
            out_path = _ensure_output_extension(out_path, out_fmt)

            if os.path.exists(out_path):
                if sg.popup_yes_no(f"Output file already exists:\n\n{out_path}\n\nOverwrite?") != "Yes":
                    continue

            print("")
            print(f"Input:  {inp}")
            print(f"Output: {out_path}")
            print(f"Hash:   {hash_type} | Format: {out_fmt} | Dedup (Full DB): {dedup}")
            print("")
            print("Starting conversion...")

            def _worker():
                try:
                    summary = convert_nsrl(inp, out_path, hash_type=hash_type, output_format=out_fmt, dedup=dedup)
                    return {"ok": True, "summary": summary, "output": out_path}
                except Exception as e:
                    return {"ok": False, "error": str(e)}

            converting = True
            window["convert"].update(disabled=True)

            window.perform_long_operation(lambda: _worker(), "-END CONVERT-")

        if event == "-END CONVERT-":
            converting = False
            window["convert"].update(disabled=not can_convert(values))
            result = values["-END CONVERT-"]
            if not result:
                continue

            if result.get("ok"):
                summary = result.get("summary", {})
                out_path = result.get("output")
                print("")
                print("Conversion complete.")
                print(f"Output written: {out_path}")
                print(f"Summary: {summary}")
                sg.popup_ok(f"Conversion complete.\n\nOutput:\n{out_path}")
            else:
                err = result.get("error", "Unknown error")
                print("")
                print("Conversion failed:")
                print(err)
                sg.popup_error(f"Conversion failed:\n\n{err}")

    window.close()

# ---------------------------
# CLI main (retained)
# ---------------------------
def main(argv):
    # Support optional flags without breaking existing positional CLI usage.
    flags = {a.lower() for a in argv[1:] if a.startswith('-')}
    dedup_enabled = ('--dedup' in flags) or ('-d' in flags)

    # Keep only non-flag positional args
    pos = [argv[0]] + [a for a in argv[1:] if not a.startswith('-')]

    if len(pos) < 3 or len(pos) > 5:
        log(f"{len(pos)-1} arguments given, 2 to 4 expected (plus optional flags)", "error")
        print_usage()
        return 2

    input_path = pos[1]
    output_path = pos[2]

    hash_type = pos[3] if len(pos) >= 4 else 'md5'
    hash_type = hash_type.lower()
    if hash_type not in ['md5', 'sha1']:
        log("Invalid hash type specified. Use 'md5' or 'sha1'.", "error")
        print_usage()
        return 2

    output_format = pos[4] if len(pos) == 5 else 'text'
    output_format = output_format.lower()
    if output_format not in ['text', 'json']:
        log("Invalid output format specified. Use 'text' or 'json'.", "error")
        print_usage()
        return 2

    output_path = _ensure_output_extension(output_path, output_format)

    log(f"Hash Format Selected: {hash_type}")
    log(f"Dedup Enabled: {dedup_enabled}")
    print_time("Start Time is:")

    try:
        summary = convert_nsrl(
            input_path,
            output_path,
            hash_type=hash_type,
            output_format=output_format,
            dedup=dedup_enabled
        )
        print_time("End Time is:")
        log(f"Output written: {output_path}")
        log(f"Summary: {summary}")
        return 0
    except Exception as e:
        log(f"Unexpected error: {e}", "error")
        LOGGER.exception("Unexpected error details")
        return 1

if __name__ == "__main__":
    if len(sys.argv) == 1:
        run_gui()
        sys.exit(0)
    sys.exit(main(sys.argv))
