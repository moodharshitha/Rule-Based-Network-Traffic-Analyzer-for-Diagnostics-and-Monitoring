from flask import Flask, jsonify
from flask_cors import CORS
from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP
import threading
import time

app = Flask(__name__)
CORS(app)

traffic_data = []

# ---------------- RULE BASED ANALYSIS ----------------
def analyze_packet(packet):
    if not packet.haslayer(IP):
        return None

    size = len(packet)
    src = packet[IP].src
    dst = packet[IP].dst
    proto = "OTHER"
    alert = "Normal"

    if packet.haslayer(TCP):
        proto = "TCP"
        if packet[TCP].flags == "S":
            alert = "Possible SYN Scan"
    elif packet.haslayer(UDP):
        proto = "UDP"
    elif packet.haslayer(ICMP):
        proto = "ICMP"
        alert = "ICMP Traffic Detected"

    if size > 1500:
        alert = "Large Packet - Possible Data Leak"

    return {
        "time": time.strftime("%H:%M:%S"),
        "source_ip": src,
        "destination_ip": dst,
        "packet_size": size,
        "protocol": proto,
        "alert": alert
    }

# ---------------- LIVE CAPTURE ----------------
def live_capture():
    def process(packet):
        result = analyze_packet(packet)
        if result:
            traffic_data.append(result)
            if len(traffic_data) > 25:
                traffic_data.pop(0)

    sniff(prn=process, store=False)

threading.Thread(target=live_capture, daemon=True).start()

# ---------------- API ROUTES ----------------
@app.route("/traffic")
def traffic():
    return jsonify(traffic_data)

@app.route("/offline")
def offline():
    packets = rdpcap("offline.pcap")
    results = []

    for pkt in packets[:25]:
        result = analyze_packet(pkt)
        if result:
            results.append(result)

    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True)
