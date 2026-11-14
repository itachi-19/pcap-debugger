#!/bin/python

import duckdb
import sys 
from core.ingest import pcap_to_duckdb
from core.agent import analyze_pcap_with_llm

if __name__ == "__main__":
    PCAP_FILE = sys.argv[1]
    
    con = duckdb.connect(database=":memory:")
    pcap_to_duckdb(PCAP_FILE, con)
    
    investigation_prompt = """
    Symptoms:
    - Users report intermittent HTTP 504 gateway timeouts and connection drops.
    - Captures were taken at our egress edge router.
    
    Goals:
    1. Determine whether packet loss/latency is originating in our network, upstream transit, or at the destination server.
    2. Assess TCP handshake delays, resets, and retransmission spikes.
    3. Generate the full formatted RCA report, including the exhaustive diagnostic playbook for anything that cannot be proven definitively from this edge capture alone.
    """
    
    analyze_pcap_with_llm(con, investigation_prompt)



# if __name__ == "__main__":
#     PCAP_FILE = "duck2.pcap" # Replace with your test PCAP
#
#     # 1. Initialize an in-memory DuckDB instance
#     con = duckdb.connect(database=":memory:")
#
#     # 2. Ingest PCAP
#     pcap_to_duckdb(PCAP_FILE, con)
#
#     # 3. Run LLM RCA
#     prompt = """
#     We are experiencing connection timeouts and HTTP service degradation.
#     1. Check TCP health (retransmissions, SYN floods, connection resets).
#     2. Check DNS lookup response codes (rcode != 0).
#     3. Pinpoint the root cause, identify the offending IP addresses, and recommend a fix.
#     """
#
#     analyze_pcap_with_llm(con, prompt)
