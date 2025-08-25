
import sys
from pathlib import Path
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Simple Parquet Editor", layout="wide")
st.title("📝 Simple Parquet DataFrame Editor")

# -----------------------------
# Resolve input file
# -----------------------------
def _get_cli_arg(flag: str) -> str | None:
    if flag in sys.argv:
        i = sys.argv.index(flag)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return None

# 1) Try CLI: --file <path> or -f <path>
file_path = _get_cli_arg("--file") or _get_cli_arg("-f")

# 2) Try query param: ?file=/path/to/file.parquet
if not file_path:
    qp = st.query_params
    file_path = qp.get("file")

# 3) Fallback default
if not file_path:
    file_path = "/mnt/data/dataframe_input.parquet"

path = Path(str(file_path))

st.caption(f"Editing file: **{path}**")

# -----------------------------
# Load
# -----------------------------
try:
    df = pd.read_parquet(path)
    st.success(f"Loaded {len(df):,} rows × {df.shape[1]} columns")
except Exception as e:
    st.error(f"Failed to read Parquet at {path}: {e}")
    st.stop()

# -----------------------------
# Edit
# -----------------------------
edited_df = st.data_editor(df, num_rows="dynamic", use_container_width=True, key="editor")

# -----------------------------
# Save back
# -----------------------------
col1, col2 = st.columns([1, 3])
with col1:
    if st.button("💾 Save back to same file"):
        try:
            edited_df.to_parquet(path, index=False)
            st.toast(f"Saved to {path}", icon="✅")
        except Exception as e:
            st.error(f"Save failed: {e}")

with col2:
    st.caption("Tip: Launch with `-- --file /path/to/file.parquet` or add `?file=/path/to/file.parquet` to the URL.")
