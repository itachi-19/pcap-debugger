#!/bin/python

import json
import duckdb

def get_db_schema(con: duckdb.DuckDBPyConnection) -> str:
    """Returns the schema of the `packets` view for LLM context."""
    df = con.execute("DESCRIBE packets;").fetchdf()
    return df.to_string(index=False)

def execute_sql(con: duckdb.DuckDBPyConnection, sql: str) -> str:
    """Executes a SQL query safely and returns tabular text or JSON."""
    # Safety: Enforce read-only queries
    forbidden = ["DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "ATTACH"]
    if any(f in sql.upper() for f in forbidden):
        return "Error: Read-only SELECT queries are allowed."
    
    try:
        # Limit rows returned to avoid blowing up LLM context window
        result_df = con.execute(sql).fetchdf().head(50)
        if result_df.empty:
            return "Query returned 0 rows."
        return result_df.to_markdown(index=False)
    except Exception as e:
        return f"SQL Error: {str(e)}"
