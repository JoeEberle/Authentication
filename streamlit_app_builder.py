from pathlib import Path

def generate_data_editor_app(app_name = 'app.py', app_path = '/users/josep/authentication/'):
    app_code = r'''
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
    '''

    application_file_name  = app_name
    out_path = Path(f"/users/josep/authentication/{application_file_name}")
    out_path.write_text(app_code, encoding="utf-8")
    print(f"Wrote minimal Streamlit editor to {out_path}")
    return app_code 


from pathlib import Path

def generate_data_editor_app_sidebar(app_name: str = "app_sidebar.py", app_path: str = "/users/josep/authentication/"):
    app_code = r'''
import os
import sys
import sqlite3
from pathlib import Path
import pandas as pd
import streamlit as st

# ---------- Page setup ----------
st.set_page_config(page_title="Data Editor (Sidebar Controls)", layout="wide")

# Title stays above the editor; all controls go to the sidebar.
st.title("📝 DataFrame Editor")

ALLOWED_EXTS = {".xlsx", ".xls", ".csv", ".parquet", ".pq", ".json"}

# ---------- Helpers ----------
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

def ext_for(fmt_label: str) -> str:
    if fmt_label.startswith("CSV"): return ".csv"
    if fmt_label.startswith("Parquet"): return ".parquet"
    if fmt_label.startswith("Excel"): return ".xlsx"
    if fmt_label.startswith("JSON"): return ".json"
    if fmt_label.startswith("SQLite"): return ".db"
    return ""

# ===========================
#        SIDEBAR UI
# ===========================
with st.sidebar:
    # --- Logo area (leave space even if not used) ---
    st.markdown("### 🌟 App Branding")
    logo_path = st.text_input("Logo file path or URL (optional)", value="", help="PNG/JPG/GIF; leave blank to skip.")
    if logo_path.strip():
        try:
            st.image(logo_path, use_container_width=True)
        except Exception:
            st.info("Could not load logo. Check the path/URL.")

    st.markdown("---")
    st.markdown("### 🔎 File Browser")

    default_root = str(Path.cwd())
    root_dir = st.text_input("Search root folder", value=default_root, help="Scans this folder and subfolders.")
    rescan = st.button("🔄 Rescan files", key="rescan")
    name_filter = st.text_input("Filename filter (contains)", value="")

    if rescan:
        scan_files.clear()  # clear cache

    file_list = scan_files(root_dir)
    if name_filter.strip():
        q = name_filter.strip().lower()
        file_list = [f for f in file_list if q in f.lower()]

    if not file_list:
        st.info("No data files found.\nSupported: .xlsx, .csv, .parquet, .pq, .json")
        st.stop()

    selected_rel = st.selectbox("Select a file (relative to root)", options=file_list, index=0, key="file_select")
    selected_path = Path(root_dir).expanduser().resolve() / selected_rel
    st.caption(f"Selected: **{selected_path}**")

# ---------- Load selected file ----------
try:
    df = load_df(selected_path)
    st.success(f"Loaded {len(df):,} rows × {df.shape[1]} columns")
except Exception as e:
    st.error(f"Failed to read {selected_path}: {e}")
    st.stop()

# ===========================
#       MAIN: EDITOR
# ===========================
edited_df = st.data_editor(
    df,
    num_rows="dynamic",
    use_container_width=True,
    key="editor"
)

# ===========================
#   SIDEBAR: SAVE OPTIONS
# ===========================
with st.sidebar:
    st.markdown("---")
    st.markdown("### 💾 Save Options")

    # --- Overwrite same file ---
    orig_ext = selected_path.suffix.lower()
    same_fmt = infer_fmt_from_ext(orig_ext)

    with st.expander("Overwrite the ORIGINAL file", expanded=False):
        if st.button(f"💾 Overwrite original ({orig_ext or 'unknown'})", key="overwrite_btn"):
            try:
                if not same_fmt:
                    st.error(f"Unsupported original format: {orig_ext}")
                else:
                    save_df(edited_df, selected_path, same_fmt)
                    st.toast(f"Saved to {selected_path}", icon="✅")
                    st.success(f"Overwrote {selected_path}")
            except Exception as e:
                st.error(f"Save failed: {e}")

    # --- Save As ---
    with st.expander("Save As… (choose folder/name/format)", expanded=True):
        default_dir = str(selected_path.parent)
        default_name = selected_path.stem

        dest_dir = st.text_input("Destination folder", value=default_dir, key="dest_dir")
        base_name = st.text_input("Filename (without extension)", value=default_name, key="base_name")

        fmt_label = st.selectbox(
            "Format",
            ["CSV (.csv)", "Parquet (.parquet)", "Excel (.xlsx)", "JSON (.json)", "SQLite (.db)"],
            index=1,
            key="fmt_label"
        )
        sqlite_table = st.text_input("SQLite table name (only for SQLite)", value="user_list", key="sqlite_tbl") \
                        if "SQLite" in fmt_label else None
        overwrite = st.checkbox("Overwrite if file exists", value=True, key="overwrite_chk")

        if st.button("💾 Save As", key="saveas_btn"):
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
                    st.toast(f"Saved to {out_path}", icon="✅")
                    st.success(f"Saved to {out_path}")
            except Exception as e:
                st.error(f"Save failed: {e}")

    st.caption("Tip: Change the search root and click Rescan to browse other folders.")
'''
    out_path = Path(app_path).expanduser() / app_name
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(app_code, encoding="utf-8")
    print(f"Wrote sidebar Streamlit editor to {out_path}")
    return app_code


from pathlib import Path

def generate_data_editor_app_sidebar_auth(
    app_name: str = "app_sidebar_auth.py",
    app_path: str = "/users/josep/authentication/",
    user_list_path: str = "/users/josep/authentication/user_list.parquet",
):
    app_code = r'''
import os
import sys
import sqlite3
from pathlib import Path
import pandas as pd
import streamlit as st

# =====================================
#            PAGE SETUP
# =====================================
st.set_page_config(page_title="Data Editor (Auth + Sidebar Controls)", layout="wide")

ALLOWED_EXTS = {
    ".xlsx", ".xls", ".csv", ".parquet", ".pq", ".json",
    ".pkl", ".pickle", ".feather"
}

# =====================================
#         AUTHENTICATION HELPERS
# =====================================
def load_user_table(parquet_path: str) -> pd.DataFrame:
    p = Path(parquet_path).expanduser()
    if not p.exists():
        raise FileNotFoundError(f"user_list parquet not found: {p}")
    df = pd.read_parquet(p)
    # Normalize expected columns
    cols = {c.lower(): c for c in df.columns}
    # Accept 'password' or 'password_hash'
    if 'password' not in cols and 'password_hash' not in cols:
        raise ValueError("user_list must contain 'password' or 'password_hash' column (hashed).")
    if 'user_id' not in cols:
        raise ValueError("user_list must contain 'user_id' column.")
    if 'fullname' not in cols and 'name' not in cols:
        # optional, but nice to have
        df['FullName'] = df.get('FullName') or df.get('Name') or df.get('full_name') or df.get('fullName')
    return df

def _bcrypt_available():
    try:
        import bcrypt  # noqa
        return True
    except Exception:
        return False

def verify_password(plain: str, stored_hash: str) -> bool:
    """
    Supports:
    - bcrypt hashes starting with $2b$ or $2a$ (requires 'bcrypt' installed)
    - SHA-256 hex digests (64 hex chars)
    """
    if not isinstance(stored_hash, str):
        return False
    s = stored_hash.strip()
    # bcrypt branch
    if s.startswith("$2b$") or s.startswith("$2a$"):
        if not _bcrypt_available():
            st.error("bcrypt hash detected but 'bcrypt' package is not installed. Try: pip install bcrypt")
            return False
        import bcrypt
        try:
            return bcrypt.checkpw(plain.encode("utf-8"), s.encode("utf-8"))
        except Exception:
            return False
    # sha256 hex fallback
    if len(s) == 64 and all(ch in "0123456789abcdef" for ch in s.lower()):
        import hashlib
        return hashlib.sha256(plain.encode("utf-8")).hexdigest() == s
    # Unknown format
    st.warning("Unknown password hash format for this user.")
    return False

@st.cache_data(show_spinner=False)
def build_user_index(user_parquet_path: str):
    """
    Returns:
      users_by_id: dict user_id -> { 'name': ..., 'hash': ... }
    """
    df = load_user_table(user_parquet_path)
    # Column resolution
    def col(*names):
        for n in names:
            if n in df.columns:
                return n
            if n.lower() in [c.lower() for c in df.columns]:
                # exact case-insensitive match
                for c in df.columns:
                    if c.lower() == n.lower():
                        return c
        return None

    col_uid = col('user_id')
    col_name = col('FullName','Name','full_name')
    col_pwd  = col('password','password_hash')

    users = {}
    for _, row in df.iterrows():
        uid = str(row[col_uid]).strip()
        nm  = str(row[col_name]) if col_name else uid
        pwdh = str(row[col_pwd]).strip()
        if uid:
            users[uid] = {'name': nm, 'hash': pwdh}
    return users

def login_ui(users_by_id: dict) -> bool:
    with st.container(border=True):
        st.subheader("🔐 Please sign in")
        with st.form("login_form", clear_on_submit=False):
            uid = st.text_input("User ID", key="login_user_id")
            pw  = st.text_input("Password", type="password", key="login_password")
            submitted = st.form_submit_button("Sign In")
        if submitted:
            if not uid or not pw:
                st.error("Enter both User ID and Password.")
                return False
            if uid not in users_by_id:
                st.error("Unknown user ID.")
                return False
            ok = verify_password(pw, users_by_id[uid]['hash'])
            if ok:
                st.session_state['auth_user_id'] = uid
                st.session_state['auth_user_name'] = users_by_id[uid]['name']
                st.toast("Welcome!", icon="✅")
                return True
            st.error("Invalid credentials.")
    return False

def logout():
    for k in ['auth_user_id','auth_user_name']:
        if k in st.session_state:
            del st.session_state[k]
    st.toast("Logged out.", icon="👋")

# =====================================
#             APP HELPERS
# =====================================
def load_df(p: Path) -> pd.DataFrame:
    ext = p.suffix.lower()
    if ext in {".parquet", ".pq"}:
        return pd.read_parquet(p)
    if ext == ".feather":
        return pd.read_feather(p)
    if ext in {".pkl", ".pickle"}:
        return pd.read_pickle(p)
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

def ext_for(fmt_label: str) -> str:
    if fmt_label.startswith("CSV"): return ".csv"
    if fmt_label.startswith("Parquet"): return ".parquet"
    if fmt_label.startswith("Excel"): return ".xlsx"
    if fmt_label.startswith("JSON"): return ".json"
    if fmt_label.startswith("SQLite"): return ".db"
    return ""

# =====================================
#            AUTH GATE
# =====================================
USER_LIST_PATH = r''' + f"'{user_list_path}'" + r'''
users_by_id = build_user_index(USER_LIST_PATH)

# If not logged in, show login UI
if 'auth_user_id' not in st.session_state:
    signed_in = login_ui(users_by_id)
    if not signed_in:
        st.stop()

# Header with user info and logout
top_cols = st.columns([1, 3, 1])
with top_cols[0]:
    st.caption(f"Signed in as **{st.session_state.get('auth_user_name','')}**")
with top_cols[2]:
    if st.button("Logout", type="secondary", use_container_width=True):
        logout()
        st.rerun()

# =====================================
#        SIDEBAR: BRAND + BROWSER
# =====================================
with st.sidebar:
    st.markdown("### 🌟 App Branding")
    logo_path = st.text_input("Logo file path or URL (optional)", value="", help="PNG/JPG/GIF; leave blank to skip.")
    if logo_path.strip():
        try:
            st.image(logo_path, use_container_width=True)
        except Exception:
            st.info("Could not load logo. Check the path/URL.")

    st.markdown("---")
    st.markdown("### 🔎 File Browser")

    default_root = str(Path.cwd())
    root_dir = st.text_input("Search root folder", value=default_root, help="Scans this folder and subfolders.")
    rescan = st.button("🔄 Rescan files", key="rescan")
    name_filter = st.text_input("Filename filter (contains)", value="")

    if rescan:
        scan_files.clear()  # clear cache

    file_list = scan_files(root_dir)
    if name_filter.strip():
        q = name_filter.strip().lower()
        file_list = [f for f in file_list if q in f.lower()]

    if not file_list:
        st.info("No data files found.\nSupported: .xlsx, .csv, .parquet, .pq, .json")
        st.stop()

    selected_rel = st.selectbox("Select a file (relative to root)", options=file_list, index=0, key="file_select")
    selected_path = Path(root_dir).expanduser().resolve() / selected_rel
    st.caption(f"Selected: **{selected_path}**")

# =====================================
#              LOAD FILE
# =====================================
try:
    df = load_df(selected_path)
    st.success(f"Loaded {len(df):,} rows × {df.shape[1]} columns")
except Exception as e:
    st.error(f"Failed to read {selected_path}: {e}")
    st.stop()

# =====================================
#           MAIN: EDITOR
# =====================================
st.title("📝 DataFrame Editor")
edited_df = st.data_editor(
    df,
    num_rows="dynamic",
    use_container_width=True,
    key="editor"
)

# =====================================
#        SIDEBAR: SAVE OPTIONS
# =====================================
with st.sidebar:
    st.markdown("---")
    st.markdown("### 💾 Save Options")

    # Overwrite same file
    orig_ext = selected_path.suffix.lower()
    same_fmt = infer_fmt_from_ext(orig_ext)

    with st.expander("Overwrite the ORIGINAL file", expanded=False):
        if st.button(f"💾 Overwrite original ({orig_ext or 'unknown'})", key="overwrite_btn"):
            try:
                if not same_fmt:
                    st.error(f"Unsupported original format: {orig_ext}")
                else:
                    save_df(edited_df, selected_path, same_fmt)
                    st.toast(f"Saved to {selected_path}", icon="✅")
                    st.success(f"Overwrote {selected_path}")
            except Exception as e:
                st.error(f"Save failed: {e}")

    # Save As
    with st.expander("Save As… (choose folder/name/format)", expanded=True):
        default_dir = str(selected_path.parent)
        default_name = selected_path.stem

        dest_dir = st.text_input("Destination folder", value=default_dir, key="dest_dir")
        base_name = st.text_input("Filename (without extension)", value=default_name, key="base_name")

        fmt_label = st.selectbox(
            "Format",
            ["CSV (.csv)", "Parquet (.parquet)", "Excel (.xlsx)", "JSON (.json)", "SQLite (.db)"],
            index=1,
            key="fmt_label"
        )
        sqlite_table = st.text_input("SQLite table name (only for SQLite)", value="user_list", key="sqlite_tbl") \
                        if "SQLite" in fmt_label else None
        overwrite = st.checkbox("Overwrite if file exists", value=True, key="overwrite_chk")

        if st.button("💾 Save As", key="saveas_btn"):
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
                    st.toast(f"Saved to {out_path}", icon="✅")
                    st.success(f"Saved to {out_path}")
            except Exception as e:
                st.error(f"Save failed: {e}")

    st.caption("Tip: Change the search root and click Rescan to browse other folders.")
'''
    out_path = Path(app_path).expanduser() / app_name
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(app_code, encoding="utf-8")
    print(f"Wrote AUTH Streamlit editor to {out_path}")
    return app_code



