import sys
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

    #using definition where 1 MB is equal to 1024 Kilobytes, which is 1024 bytes => (1024 * 1024)
    return total_bytes / (1024 * 1024) 



if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python bandwidth.py <.pcapng file>, <ip_address>")
        sys.exit(1)
    
    pcap_path = sys.argv[1]
    ip_address = sys.argv[2]  
    total_megabytes = calculate_bandwidth_by_ip_address(pcap_path, ip_address)
    print(f"Total Data Used: {total_megabytes:.2f} MB")
