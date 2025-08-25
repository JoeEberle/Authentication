import pandas as pd

def get_user_list_excel(file_name = "user_list.xlsx"):
    """
    returns a dataframe of users. Reads Excel File into a Dataframe 
    """
    try:
        df_user_list = pd.read_excel(file_name) # Reads Excel File into a Dataframe
        if len(df_user_list) > 1:
                print(f"✅ Read File Successfully : {df_user_list.shape[0]} ")
        return df_user_list
    except Exception as e:
        print(f"❌ File Read failed: {e}")
        return False


import pandas as pd
import sqlite3

def save_user_list_excel(df, file_name="user_list.xlsx"):
    """Save DataFrame to Excel file."""
    df.to_excel(file_name, index=False)
    print(f"✅ Saved {len(df):,} rows to {file_name}")
    return file_name

def save_user_list_parquet(df, file_name="user_list.parquet"):
    """Save DataFrame to Parquet file."""
    df.to_parquet(file_name, index=False)
    print(f"✅ Saved {len(df):,} rows to {file_name}")
    return file_name

def save_user_list_sqlite(df, db_file="user_list.db", table_name="user_list"):
    """Save DataFrame to SQLite database table."""
    try:
        with sqlite3.connect(db_file) as conn:
            df.to_sql(table_name, conn, if_exists="replace", index=False)
        print(f"✅ Saved {len(df):,} rows to {db_file} (table: {table_name})")
        return db_file
    except Exception as e:
        print(f"❌ Failed to save to SQLite: {e}")
        return None


