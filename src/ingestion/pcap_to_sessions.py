import os
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
from tqdm import tqdm

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "../../"))

RAW_PATH = os.path.join(PROJECT_ROOT, "data/raw")
PROCESSED_PATH = os.path.join(PROJECT_ROOT, "data/processed")


IDLE_THRESHOLD = 2.0      # seconds
LARGE_PKT = 1000          # bytes
SMALL_PKT = 200           # bytes


def classify_event(row, prev_time):
    if prev_time is not None and (row["timestamp"] - prev_time) > IDLE_THRESHOLD:
        return "IDLE"

    if row["protocol"] == 17:
        return "UDP_PACKET"

    if row["flags"] == "S":
        return "TCP_SYN"
    if row["flags"] == "SA":
        return "TCP_HANDSHAKE"
    if row["flags"] in ("F", "FA", "R"):
        return "SESSION_END"

    if row["length"] > LARGE_PKT:
        return "LARGE_TRANSFER"
    if row["length"] < SMALL_PKT:
        return "SMALL_TRANSFER"

    return "PACKET"


def parse_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    rows = []

    for pkt in tqdm(packets, desc=f"Parsing {os.path.basename(pcap_file)}"):
        if IP not in pkt:
            continue

        row = {
            "timestamp": float(pkt.time),
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "protocol": pkt[IP].proto,
            "length": len(pkt),
            "src_port": None,
            "dst_port": None,
            "flags": None
        }

        if TCP in pkt:
            row["src_port"] = pkt[TCP].sport
            row["dst_port"] = pkt[TCP].dport
            row["flags"] = str(pkt[TCP].flags)
        elif UDP in pkt:
            row["src_port"] = pkt[UDP].sport
            row["dst_port"] = pkt[UDP].dport

        rows.append(row)

    return pd.DataFrame(rows)


def build_sessions(df, source_name):
    df["session_id"] = (
        df["src_ip"] + "_" +
        df["dst_ip"] + "_" +
        df["src_port"].astype(str) + "_" +
        df["dst_port"].astype(str) + "_" +
        df["protocol"].astype(str)
    )

    session_rows = []

    for session_id, group in df.groupby("session_id"):
        group = group.sort_values("timestamp")
        prev_time = None

        for _, row in group.iterrows():
            evt = classify_event(row, prev_time)
            prev_time = row["timestamp"]

            session_rows.append({
                "session_id": session_id,
                "timestamp": row["timestamp"],
                "event": evt,
                "length": row["length"],
                "source_pcap": source_name   # TRACEABILITY ONLY
            })

    return pd.DataFrame(session_rows)


if __name__ == "__main__":
    os.makedirs(PROCESSED_PATH, exist_ok=True)

    all_sessions = []

    for pcap in os.listdir(RAW_PATH):
        if not pcap.endswith(".pcap"):
            continue

        print(f"[INFO] Processing {pcap}")
        df_packets = parse_pcap(os.path.join(RAW_PATH, pcap))
        df_sessions = build_sessions(df_packets, source_name=pcap)

        all_sessions.append(df_sessions)

    # Merge everything into ONE dataset
    final_df = pd.concat(all_sessions, ignore_index=True)

    out_file = os.path.join(PROCESSED_PATH, "all_sessions.csv")
    final_df.to_csv(out_file, index=False)

    print(f"\n[✅ DONE] Saved unified dataset:")
    print(f"     {out_file}")
    print(f"     Total events: {len(final_df)}")
    print(f"     Total sessions: {final_df['session_id'].nunique()}")
