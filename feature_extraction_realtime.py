from scapy.all import rdpcap, IP, TCP, UDP, Raw
import pandas as pd
import numpy as np
from collections import defaultdict

pcap_file = "real_time_AES.pcap"
packets = rdpcap(pcap_file)

flows = defaultdict(lambda: {
    "packet_count": 0,
    "byte_count": 0,
    "src_bytes": 0,
    "dst_bytes": 0,
    "start_time": None,
    "end_time": None,
    "protocol": 0,
    "payload_entropy": [],
    "src": None,
    "dst": None,
    "sport": None,
    "dport": None,
})

def calc_entropy(data):
    if not data:
        return 0
    arr = np.frombuffer(data, dtype=np.uint8)
    probs = np.bincount(arr, minlength=256) / len(arr)
    probs = probs[probs > 0]
    return -np.sum(probs * np.log2(probs))

for pkt in packets:
    if IP not in pkt:
        continue

    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = pkt[IP].proto
    sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
    dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
    fid = (src, dst, sport, dport, proto)
    flow = flows[fid]

    flow["packet_count"] += 1
    flow["byte_count"] += len(pkt)
    flow["protocol"] = proto
    flow["src"] = src
    flow["dst"] = dst
    flow["sport"] = sport
    flow["dport"] = dport
    flow["end_time"] = pkt.time
    flow["start_time"] = flow["start_time"] or pkt.time

    if Raw in pkt:
        entropy = calc_entropy(bytes(pkt[Raw].load))
        flow["payload_entropy"].append(entropy)
        if sport < dport:
            flow["src_bytes"] += len(pkt[Raw].load)
        else:
            flow["dst_bytes"] += len(pkt[Raw].load)

rows = []
for fid, data in flows.items():
    duration = data["end_time"] - data["start_time"] if data["start_time"] else 0
    avg_entropy = np.mean(data["payload_entropy"]) if data["payload_entropy"] else 0
    avg_pkt_size = data["byte_count"] / data["packet_count"] if data["packet_count"] > 0 else 0

    rows.append({
        "src_ip": data["src"],
        "dst_ip": data["dst"],
        "protocol_type": data["protocol"],
        "src_bytes": data["src_bytes"],
        "dst_bytes": data["dst_bytes"],
        "duration": duration,
        "packet_count": data["packet_count"],
        "byte_count": data["byte_count"],
        "avg_packet_size": avg_pkt_size,
        "payload_entropy": avg_entropy
    })

df = pd.DataFrame(rows)
df.to_csv("extracted_features.csv", index=False)
print(f"Extracted {len(df)} flows → saved to extracted_features.csv")
