import json
import openai
import duckdb
from core.tools import execute_sql

tools = [
    {
        "type": "function",
        "function": {
            "name": "run_sql_query",
            "description": (
                "Executes a read-only SQL query against the DuckDB `packets` view. "
                "Always check column names via DESCRIBE or query known columns: "
                "frame_number, timestamp, frame_len, protocols, src_ip, dst_ip, src_port, dst_port, "
                "is_syn, is_rst, is_fin, is_retransmission, ack_rtt, dns_is_response, dns_rcode, http_status. "
                "Example: SELECT src_ip, COUNT(*) FROM packets WHERE is_rst = true GROUP BY src_ip;"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Valid DuckDB SQL SELECT query."
                    }
                },
                "required": ["query"],
            },
        },
    }
]

def analyze_pcap_with_llm(con: duckdb.DuckDBPyConnection, user_goal: str = "Perform a Root Cause Analysis"):
    client = openai.OpenAI(
        base_url = "http://localhost:11434/v1",
        api_key =  "ollama"
    )
    
    # Verify the table actually exists and has rows before querying
    try:
        count_check = con.execute("SELECT COUNT(*) FROM packets;").fetchone()[0]
        schema_df = con.execute("DESCRIBE packets;").fetchdf()
        schema_info = schema_df[["column_name", "column_type"]].to_markdown(index=False)
        print(f"[*] Ingested PCAP verified: {count_check} packets ready in DuckDB.")
    except Exception as e:
        print(f"[!] Error verifying `packets` table: {e}")
        return

#     system_prompt = f"""You are an autonomous Network Troubleshooting Specialist and SRE Incident Commander.
# Your objective is to independently investigate network trace data in DuckDB and generate an exhaustive Root Cause Analysis (RCA).
#
# DATABASE DETAILS:
# Table: `packets`
# Total Packets Available: {count_check}
#
# SCHEMA:
# {schema_info}
#
# STRICT SQL SYNTAX RULES:
# 1. Columns `is_syn`, `is_rst`, `is_fin`, `is_retransmission` are BOOLEAN.
#    Use them directly: `WHERE is_rst` or `WHERE is_rst = true`.
# 2. Do NOT invent columns. Only use columns from the schema above.
# 3. Do NOT use dots or spaces in column aliases (use `AS tcp_resets`, NOT `AS tcp.resets`).
# 4. To aggregate flags, use:
#    `SELECT SUM(CASE WHEN is_rst THEN 1 ELSE 0 END) AS reset_count FROM packets;`
#
# INVESTIGATION PROTOCOL:
# - You are an automated system. DO NOT chat, do not say 'Let me know if you would like me to try another query', and do not provide pleasantries.
# - Execute SQL queries using the `run_sql_query` tool.
# - Drill down through the data until you have concrete IP addresses, timestamps, and protocol statistics.
# - When you have completed all queries and have enough facts, synthesize the final RCA report in Markdown.
# """
    system_prompt = f"""You are an autonomous Network Troubleshooting Specialist and SRE Incident Commander.
Your objective is to independently investigate network trace data in DuckDB and generate an exhaustive Root Cause Analysis (RCA).

DATABASE DETAILS:
Table: `packets`
Total Packets Available: {count_check}

SCHEMA:
{schema_info}

INVESTIGATION RULES:
1. You must execute at least 3 distinct SQL queries via `run_sql_query` to gather hard telemetry (e.g., traffic volume, TCP resets/retransmissions, latency distribution) before writing any final summary.
2. The final response must ONLY be a structured Markdown RCA report summarizing the exact findings, IP addresses, counts, and metrics retrieved from the DuckDB queries.
3. Do NOT provide conversational filler, do not ask the user for follow-up, and do not summarize prematurely.
"""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_goal}
    ]

    max_steps = 10
    for step in range(max_steps):
        # On the first 2 steps, FORCE the model to call a tool so it cannot slip into chatbot mode
        current_tool_choice = "required" if step < 4 else "auto"

        response = client.chat.completions.create(
            model="llama3.1:8b",  # gpt-4o handles tools much better than gpt-4o-mini
            messages=messages,
            tools=tools,
            # tool_choice="required",
            tool_choice=current_tool_choice,
            max_completion_tokens=4000,
            temperature=0.1  # Low temperature prevents hallucinatory SQL
        )

        choice = response.choices[0]
        msg = choice.message
        messages.append(msg)

        # Handle tool execution
        if msg.tool_calls:
            for tool_call in msg.tool_calls:
                if tool_call.function.name == "run_sql_query":
                    try:
                        args = json.loads(tool_call.function.arguments)
                        query = args.get("query", "")
                    except Exception:
                        query = tool_call.function.arguments

                    print(f"\n[Step {step+1} - SQL Run]: {query}")
                    query_result = execute_sql(con, query)
                    print(f"[Step {step+1} - Result Sample]:\n{query_result[:350]}\n")

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "name": "run_sql_query",
                        "content": query_result
                    })
            continue
        # Fallback parser: if the model leaked raw JSON tool syntax into text instead of tool_calls
        if "run_sql_query" in (msg.content or "") and "parameters" in (msg.content or ""):
            import re
            json_match = re.search(r'\{.*\}', msg.content, re.DOTALL)
            if json_match:
                try:
                    parsed_json = json.loads(json_match.group(0))
                    query = parsed_json.get("parameters", {}).get("query", "")
                    if query:
                        print(f"\n[Step {step+1} - Recovered SQL Run]: {query}")
                        query_result = execute_sql(con, query)
                        print(f"[Step {step+1} - Result Sample]:\n{query_result[:350]}\n")
                        messages.append({
                            "role": "tool",
                            "tool_call_id": "recovered_call",
                            "name": "run_sql_query",
                            "content": query_result
                        })
                        continue
                except Exception:
                    pass

# If it tries to exit too early with text before completing enough steps, nudge it back
        text_lower = (msg.content or "").lower()
        if step < 3 and len(msg.content) < 400:
            print("[*] Incomplete investigation detected. Forcing further tool queries...")
            messages.append({
                "role": "user",
                "content": "You have not completed the telemetry analysis. Run another SQL query to verify retransmissions or error metrics before concluding."
            })
            continue
        # # Detect and reject conversational surrender
        # text_lower = (msg.content or "").lower()
        # conversational_phrases = ["let me know", "would you like", "try another query", "if you want"]
        # if any(phrase in text_lower for phrase in conversational_phrases) and step < max_steps - 1:
        #     print("[*] Detected conversational fallback. Nudging model back into investigation...")
        #     messages.append({
        #         "role": "user",
        #         "content": "You are not interacting with an end-user. Do not ask what to do. Inspect the schema, run the required diagnostic SQL queries, identify the offending IP addresses, and write the final RCA."
        #     })
        #     continue

        # If it genuinely finished without tool calls and without giving up:
        print("\n================ FINAL RCA REPORT ================\n")
        print(msg.content)
        return msg.content
