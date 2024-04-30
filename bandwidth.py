import pyshark

def calculate_bandwidth_by_ip_address(pcap_file, ip_address):

    display_filter = f'ip.addr == {ip_address}'
    cap = pyshark.FileCapture(pcap_file, display_filter=display_filter)
    total_bytes = 0

    try:
        for packet in cap:
            if 'IP' in packet:
                total_bytes += int(packet.ip.len)
    except Exception as e:
        print(f"Error processing packet: {e}")
    finally:
        cap.close()

    return total_bytes / (1024 * 1024)  


if __name__ == "__main__":
    pcap_path = r'Fortnite Game.pcapng'
    ip_address = '34.83.216.43'  
    total_megabytes = calculate_bandwidth_by_ip_address(pcap_path, ip_address)
    print(f"Total Data Used: {total_megabytes:.2f} MB")
