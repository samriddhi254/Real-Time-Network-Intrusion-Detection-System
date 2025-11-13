from scapy.all import sniff, Raw, IP, TCP, UDP, wrpcap, get_if_list
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ---------------- CONFIG ----------------
PACKET_COUNT = 100
INTERFACE = "Wi-Fi"  # change as needed
OUTPUT_FILE = "real_time_AES.pcap"
AES_KEY = get_random_bytes(16)  # 128-bit key
encrypted_packets = []

# ---------------- HELPERS ----------------
def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data))

def process_packet(pkt):
    """Encrypts payload and fixes checksums."""
    if Raw in pkt:
        payload = bytes(pkt[Raw].load)
        pkt[Raw].load = encrypt_aes(payload, AES_KEY)

        if IP in pkt:
            del pkt[IP].len
            del pkt[IP].chksum
        if TCP in pkt:
            del pkt[TCP].chksum
        if UDP in pkt:
            del pkt[UDP].chksum

    encrypted_packets.append(pkt)
    print(f"Encrypted packet: {len(pkt)} bytes")

# ---------------- MAIN ----------------
print("Available interfaces:", get_if_list())
print(f"Capturing {PACKET_COUNT} packets on {INTERFACE} ...")

sniff(iface=INTERFACE, prn=process_packet, count=PACKET_COUNT)
wrpcap(OUTPUT_FILE, encrypted_packets)

print(f"AES encrypted packets saved to {OUTPUT_FILE}")
print(f"AES key (save for decryption): {AES_KEY.hex()}")
