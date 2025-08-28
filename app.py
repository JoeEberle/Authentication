
import os
import sys
import sqlite3
from pathlib import Path
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Data Editor", layout="wide")
st.title("📝 DataFrame Editor")

ALLOWED_EXTS = {".xlsx", ".xls", ".csv", ".parquet", ".pq", ".json"}

# -----------------------------
# Helpers
# -----------------------------
def load_df(p: Path) -> pd.DataFrame:
    ext = p.suffix.lower()
    if ext in {".parquet", ".pq"}:
        return pd.read_parquet(p)
    if ext in {".csv", ".txt"}:
        return pd.read_csv(p)
    if ext in {".xlsx", ".xls"}:
        return pd.read_excel(p)
    if ext == ".json":
        # Try JSON Lines first, then array
        try:
            return pd.read_json(p, lines=True)
        except ValueError:
            return pd.read_json(p)
    raise ValueError(f"Unsupported file type: {ext}")

def save_df(df: pd.DataFrame, p: Path, fmt: str, sqlite_table: str | None = None):
    if fmt == "csv":
        df.to_csv(p, index=False)
    elif fmt == "parquet":
        df.to_parquet(p, index=False)
    elif fmt == "excel":
        df.to_excel(p, index=False)
    elif fmt == "json":
        df.to_json(p, orient="records", indent=2, date_format="iso", force_ascii=False)
    elif fmt == "sqlite":
        if not sqlite_table:
            raise ValueError("Please provide a SQLite table name.")
        with sqlite3.connect(p) as conn:
            df.to_sql(sqlite_table, conn, if_exists="replace", index=False)
    else:
        raise ValueError(f"Unknown format: {fmt}")

@st.cache_data(show_spinner=False)
def scan_files(root_dir: str) -> list[str]:
    """Return sorted list of relative file paths under root that match ALLOWED_EXTS."""
    root = Path(root_dir).expanduser().resolve()
    results: list[str] = []
    if not root.exists():
        return results
    for ext in ALLOWED_EXTS:
        for p in root.rglob(f"*{ext}"):
            try:
                rel = p.relative_to(root).as_posix()
            except Exception:
                rel = str(p)
            results.append(rel)
    return sorted(set(results), key=lambda s: s.lower())

def infer_fmt_from_ext(ext: str) -> str | None:
    ext = ext.lower()
    if ext in {".csv", ".txt"}:
        return "csv"
    if ext in {".parquet", ".pq"}:
        return "parquet"
    if ext in {".xlsx", ".xls"}:
        return "excel"
    if ext == ".json":
        return "json"
    return None

# -----------------------------
# Choose search root
# -----------------------------
default_root = str(Path.cwd())
root_dir = st.text_input("Search root folder", value=default_root, help="Scans this folder and subfolders for data files.")
rescan = st.button("🔄 Rescan")
name_filter = st.text_input("Filter filenames (contains)", value="")

if rescan:
    scan_files.clear()  # clear cache

file_list = scan_files(root_dir)
if name_filter.strip():
    q = name_filter.strip().lower()
    file_list = [f for f in file_list if q in f.lower()]

if not file_list:
    st.info("No data files found. Supported: .xlsx, .csv, .parquet, .pq, .json")
    st.stop()

selected_rel = st.selectbox("Select a file to edit (relative to search root)", options=file_list, index=0)
selected_path = Path(root_dir).expanduser().resolve() / selected_rel
st.caption(f"Selected: **{selected_path}**")

# -----------------------------
# Load
# -----------------------------
try:
    df = load_df(selected_path)
    st.success(f"Loaded {len(df):,} rows × {df.shape[1]} columns")
except Exception as e:
    st.error(f"Failed to read {selected_path}: {e}")
    st.stop()

# -----------------------------
# Edit
# -----------------------------
edited_df = st.data_editor(df, num_rows="dynamic", use_container_width=True, key="editor")

st.divider()
st.subheader("💾 Save options")

# -----------------------------
# Overwrite SAME file
# -----------------------------
orig_ext = selected_path.suffix.lower()
same_fmt = infer_fmt_from_ext(orig_ext)

c1, c2 = st.columns([1, 3])
with c1:
    if st.button(f"💾 Overwrite same file ({orig_ext or 'unknown'})"):
        try:
            if not same_fmt:
                st.error(f"Unsupported original format: {orig_ext}")
            else:
                save_df(edited_df, selected_path, same_fmt)
                st.toast(f"Saved to {selected_path}", icon="✅")
        except Exception as e:
            st.error(f"Save failed: {e}")
with c2:
    st.caption("Writes to the same folder and filename in the original format.")

st.divider()

# -----------------------------
# Save AS (choose folder, name, and format)
# -----------------------------
st.markdown("**Save As…** Choose a destination folder, filename, and format.")

default_dir = str(selected_path.parent)
default_name = selected_path.stem

sa1, sa2 = st.columns(2)
with sa1:
    dest_dir = st.text_input("Destination folder", value=default_dir, key="dest_dir")
with sa2:
    base_name = st.text_input("Filename (without extension)", value=default_name, key="base_name")

fmt_label = st.selectbox("Format", ["CSV (.csv)", "Parquet (.parquet)", "Excel (.xlsx)", "JSON (.json)", "SQLite (.db)"], index=1)
sqlite_table = st.text_input("SQLite table name (if saving to SQLite)", value="user_list") if "SQLite" in fmt_label else None
overwrite = st.checkbox("Overwrite if file exists", value=True)

def ext_for(fmt_label: str) -> str:
    if fmt_label.startswith("CSV"): return ".csv"
    if fmt_label.startswith("Parquet"): return ".parquet"
    if fmt_label.startswith("Excel"): return ".xlsx"
    if fmt_label.startswith("JSON"): return ".json"
    if fmt_label.startswith("SQLite"): return ".db"
    return ""

if st.button("💾 Save As"):
    try:
        out_dir = Path(dest_dir).expanduser()
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{base_name}{ext_for(fmt_label)}"
        exists = out_path.exists()
        if exists and not overwrite and not fmt_label.startswith("SQLite"):
            st.error(f"File exists: {out_path}. Uncheck 'Overwrite' or change the name.")
        else:
            fmt = "sqlite" if "SQLite" in fmt_label else infer_fmt_from_ext(out_path.suffix)
            if not fmt:
                raise ValueError(f"Cannot infer format from extension: {out_path.suffix}")
            save_df(edited_df, out_path, fmt, sqlite_table=sqlite_table)
            st.success(f"Saved to {out_path}")
    except Exception as e:
        st.error(f"Save failed: {e}")

st.caption("Default search root is the current working directory. Change it above and click Rescan to search elsewhere.")
