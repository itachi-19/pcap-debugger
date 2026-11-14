#!/bin/python
import subprocess
import duckdb
import os

def pcap_to_duckdb(pcap_path: str, con: duckdb.DuckDBPyConnection):
    """
    Extracts key protocol fields directly from tshark into a TSV file,
    then loads it directly into DuckDB with exact typed columns.
    """
    tsv_path = f"{pcap_path}.tsv"

    # Define the exact Wireshark fields we need
    fields = [
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "frame.len",
        "-e", "frame.protocols",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.reset",
        "-e", "tcp.flags.fin",
        "-e", "tcp.analysis.retransmission",
        "-e", "tcp.analysis.ack_rtt",
        "-e", "dns.flags.response",
        "-e", "dns.flags.rcode",
        "-e", "http.response.code"
    ]

    # Command exports tab-separated values (TSV) with column headers
    cmd = [
        "tshark",
        "-r", pcap_path,
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=\t",
        "-E", "occurrence=f"  # Take the first occurrence if multiple exist
    ] + fields

    print(f"[*] Extracting packet metrics from {pcap_path} via tshark...")
    with open(tsv_path, "w") as out:
        subprocess.run(cmd, stdout=out, check=True)

    print("[*] Ingesting into DuckDB table `packets`...")
    
    # Read directly from TSV and build clean typed columns
    con.execute(f"""
        CREATE OR REPLACE TABLE raw_packets AS 
        SELECT * FROM read_csv_auto('{tsv_path}', delim='\t', header=true);
    """)

    # Create the unified `packets` table the LLM queries
    # con.execute("""
    #     CREATE OR REPLACE VIEW packets AS
    #     SELECT
    #         "frame.number"::BIGINT AS frame_number,
    #         "frame.time_epoch"::DOUBLE AS timestamp,
    #         "frame.len"::INT AS frame_len,
    #         "frame.protocols"::VARCHAR AS protocols,
    #
    #         -- Unified IP and Port fields
    #         "ip.src"::VARCHAR AS src_ip,
    #         "ip.dst"::VARCHAR AS dst_ip,
    #         COALESCE("tcp.srcport", "udp.srcport")::INT AS src_port,
    #         COALESCE("tcp.dstport", "udp.dstport")::INT AS dst_port,
    #
    #         -- TCP flags & anomalies
    #         ("tcp.flags.syn" = '1') AS is_syn,
    #         ("tcp.flags.reset" = '1') AS is_rst,
    #         ("tcp.flags.fin" = '1') AS is_fin,
    #         ("tcp.analysis.retransmission" = '1') AS is_retransmission,
    #         TRY_CAST("tcp.analysis.ack_rtt" AS DOUBLE) AS ack_rtt,
    #
    #         -- DNS and HTTP indicators
    #         TRY_CAST("dns.flags.response" AS INT) AS dns_is_response,
    #         TRY_CAST("dns.flags.rcode" AS INT) AS dns_rcode,
    #         TRY_CAST("http.response.code" AS INT) AS http_status
    #     FROM raw_packets;
    # """)
# Create the unified `packets` table the LLM queries
    con.execute("""
        CREATE OR REPLACE VIEW packets AS
        SELECT
            TRY_CAST("frame.number" AS BIGINT) AS frame_number,
            TRY_CAST("frame.time_epoch" AS DOUBLE) AS timestamp,
            TRY_CAST("frame.len" AS INT) AS frame_len,
            "frame.protocols"::VARCHAR AS protocols,
            
            -- Unified IP and Port fields
            "ip.src"::VARCHAR AS src_ip,
            "ip.dst"::VARCHAR AS dst_ip,
            COALESCE(
                TRY_CAST("tcp.srcport" AS INT), 
                TRY_CAST("udp.srcport" AS INT)
            ) AS src_port,
            COALESCE(
                TRY_CAST("tcp.dstport" AS INT), 
                TRY_CAST("udp.dstport" AS INT)
            ) AS dst_port,
            
            -- TCP flags & anomalies (checking for '1' or 1 safely)
            TRY_CAST("tcp.flags.syn" AS INT) = 1 AS is_syn,
            TRY_CAST("tcp.flags.reset" AS INT) = 1 AS is_rst,
            TRY_CAST("tcp.flags.fin" AS INT) = 1 AS is_fin,
            TRY_CAST("tcp.analysis.retransmission" AS INT) = 1 AS is_retransmission,
            TRY_CAST("tcp.analysis.ack_rtt" AS DOUBLE) AS ack_rtt,
            
            -- DNS and HTTP indicators
            TRY_CAST("dns.flags.response" AS INT) AS dns_is_response,
            TRY_CAST("dns.flags.rcode" AS INT) AS dns_rcode,
            TRY_CAST("http.response.code" AS INT) AS http_status
        FROM raw_packets;
    """)
    # Clean up intermediate file
    if os.path.exists(tsv_path):
        os.remove(tsv_path)

    print("[✓] Ingestion complete. Table `packets` is ready for LLM queries.")
