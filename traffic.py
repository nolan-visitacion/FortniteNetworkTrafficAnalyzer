import sys
import pyshark
from collections import defaultdict
import matplotlib.pyplot as plt

def analyze_traffic_patterns(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    packet_count = defaultdict(int)
    time_stamps = []
    data_volumes = []

    for packet in cap:
        try:
            if 'IP' in packet:
                protocol = packet.transport_layer
                packet_count[protocol] += 1
                time_stamps.append(float(packet.sniff_timestamp))
                data_volumes.append(int(packet.ip.len))
        except AttributeError:
            continue

    cap.close()
    return packet_count, time_stamps, data_volumes

def plot_traffic(time_stamps, data_volumes):
    relative_timestamps = [ts - min(time_stamps) for ts in time_stamps]
    plt.figure(figsize=(10, 5))
    plt.plot(relative_timestamps, data_volumes, label='Data Volume Over Time')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Data Volume (bytes)')
    plt.title('Traffic Data Volume Over Time')
    plt.legend()
    plt.show()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <.pcap file>")
        sys.exit(1)
    
    pcap_path = sys.argv[1]
    packet_count, time_stamps, data_volumes = analyze_traffic_patterns(pcap_path)
    for protocol, count in packet_count.items():
        if protocol is None: 
            print('None: {}'.format(count))
        else:
            print('{}: {}'.format(protocol, count))
    plot_traffic(time_stamps, data_volumes)