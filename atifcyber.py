import socket
import threading
import paramiko
import pyshark
from scapy.all import ARP, Ether, srp

# Function to get MAC address from IP
def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None

# Function to print the banner
def print_banner(service):
    banner = f"""
*********************************************
*                                           *
*               Atif Cyber                  *
*                                           *
*        {service} Access Attempt Detected  *
*                                           *
*********************************************
"""
    print(banner)

# Function to handle captured packets
def packet_callback(packet):
    if 'IP' in packet:
        ip_src = packet.ip.src
        mac_src = get_mac(ip_src)
        service = packet.transport_layer if 'TCP' in packet else 'Unknown'
        print_banner(service)
        print(f"Source IP: {ip_src}")
        print(f"Source MAC: {mac_src}")

# Start packet capturing in a separate thread
def start_packet_capture():
    capture = pyshark.LiveCapture(interface='ens33', bpf_filter='tcp')
    capture.apply_on_packets(packet_callback)

# Fake SSH service
def handle_ssh_client(client):
    client.close()

def start_fake_ssh_server():
    host_key = paramiko.RSAKey.generate(2048)
    server = paramiko.Transport((HOST, 22))
    server.add_server_key(host_key)
    server.start_server(server=paramiko.ServerInterface())

    while True:
        client = server.accept()
        if client is not None:
            handle_ssh_client(client)

# Fake Telnet service
def handle_telnet_client(client):
    client.send(b"Welcome to the fake Telnet service!\n")
    client.close()

def start_fake_telnet_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, 2323))  # Changed port to 2323
    server.listen(5)
    while True:
        client, _ = server.accept()
        handle_telnet_client(client)

# Fake SQL service
def handle_sql_client(client):
    client.send(b"Welcome to the fake SQL service!\n")
    client.close()

def start_fake_sql_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, 1445))  # Changed port to 1445
    server.listen(5)
    while True:
        client, _ = server.accept()
        handle_sql_client(client)

# Main function to start all services
if __name__ == "__main__":
    HOST = '0.0.0.0'

    # Welcome message
    welcome_message = """
**************************************************
*                                                *
*           Welcome to Atif Cyber World          *
*                                                *
*     If you are coming here, there must be a    *
*                    reason.                     *
*   This is a honeypot designed to capture and   *
*      monitor access attempts on various        *
*                  fake services.                *
*                                                *
*           Proceed with caution!                *
**************************************************
"""
    print(welcome_message)

    # Start packet capture thread
    capture_thread = threading.Thread(target=start_packet_capture)
    capture_thread.start()

    # Start fake SSH server thread
    ssh_thread = threading.Thread(target=start_fake_ssh_server)
    ssh_thread.start()

    # Start fake Telnet server thread
    telnet_thread = threading.Thread(target=start_fake_telnet_server)
    telnet_thread.start()

    # Start fake SQL server thread
    sql_thread = threading.Thread(target=start_fake_sql_server)
    sql_thread.start()

    print("Fake services are running and capturing access attempts...")
