import pyshark

def calculate_bandwidth(pcap_file):
    cap = pyshark.FileCapture(pcap_file)

    total_bytes = 0
    for packet in cap:
        try:
            if 'IP' in packet:
                total_bytes += int(packet.ip.len)
        except AttributeError:
            continue

    cap.close()


    total_megabytes = total_bytes / (1024 * 1024)
    return total_megabytes

def calculate_bandwidth_by_port(pcap_file, port):

    filter_str = f"udp port {port}"
    cap = pyshark.FileCapture(pcap_file, display_filter=filter_str)

    total_bytes = 0
    for packet in cap:
        try:
            if 'IP' in packet:
                total_bytes += int(packet.ip.len)
        except AttributeError:
            continue

    cap.close()
    return total_bytes / (1024 * 1024)  



if __name__ == "__main__":
    pcap_path = r'C:\Users\nolan\OneDrive\Documents\School\CPE 400\Project\Fortnite Game.pcapng'
    fortnite_port = 57269  
    total_megabytes = calculate_bandwidth_by_port(pcap_path, fortnite_port)
    print(f"Total Data Used: {total_megabytes:.2f} MB")
