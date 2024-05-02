import sys
import pyshark
from collections import defaultdict
import matplotlib.pyplot as plt

def analyze_traffic_patterns(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    data_by_protocol = defaultdict(lambda: {'timestamps': [], 'volumes': []})
    protocol_count = defaultdict(int)

    for packet in cap:
        try:
            if 'IP' in packet:
                protocol = packet.transport_layer if packet.transport_layer else 'Other'
                timestamp = float(packet.sniff_timestamp)
                length = int(packet.ip.len)
                data_by_protocol[protocol]['timestamps'].append(timestamp)
                data_by_protocol[protocol]['volumes'].append(length)
                protocol_count[protocol] += 1

        except AttributeError:
            continue

    cap.close()
    return data_by_protocol, protocol_count

def plot_traffic(data_by_protocol):
    plt.figure(figsize=(10, 5))
    for protocol, data in data_by_protocol.items():
        if data['timestamps']:
            relative_timestamps = [ts - min(data['timestamps']) for ts in data['timestamps']]
            plt.plot(relative_timestamps, data['volumes'], label=f'{protocol} Traffic')

    plt.xlabel('Time (seconds)')
    plt.ylabel('Data Volume (bytes)')
    plt.title('Traffic Data Volume Over Time by Protocol: Game 1')
    plt.legend()
    plt.show()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python traffic.py <.pcapng file>")
        sys.exit(1)
    
    pcap_path = sys.argv[1]
    data_by_protocol, protocol_count = analyze_traffic_patterns(pcap_path)
    for protocol, count in protocol_count.items():
        print(f'{protocol}: {count}')
    plot_traffic(data_by_protocol)