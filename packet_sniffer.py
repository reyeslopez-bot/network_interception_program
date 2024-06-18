import socket
import os
import struct
import logging
from ctypes import *
from logging.handlers import RotatingFileHandler
from time import time, sleep
import threading
import argparse

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    filename="packet_sniffer.log",
    filemode="w",
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger()
handler = RotatingFileHandler("packet_sniffer.log", maxBytes=1000000, backupCount=5)
logger.addHandler(handler)

# Host to listen on
host = "0.0.0.0"

# ARP packet structure
class ARP(Structure):
    _fields_ = [
        ("htype", c_ushort),
        ("ptype", c_ushort),
        ("hlen", c_ubyte),
        ("plen", c_ubyte),
        ("operation", c_ushort),
        ("sha", c_ubyte * 6),  # Sender hardware address
        ("spa", c_ubyte * 4),  # Sender protocol address
        ("tha", c_ubyte * 6),  # Target hardware address
        ("tpa", c_ubyte * 4)   # Target protocol address
    ]

def parse_arp_packet(packet):
    arp_header = ARP(packet)
    return {
        "operation": socket.ntohs(arp_header.operation),
        "sender_mac": ':'.join('%02x' % b for b in arp_header.sha),
        "sender_ip": socket.inet_ntoa(bytes(arp_header.spa)),
        "target_mac": ':'.join('%02x' % b for b in arp_header.tha),
        "target_ip": socket.inet_ntoa(bytes(arp_header.tpa))
    }

# IP header class
class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32)
    ]
    
    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i + 1] if i + 1 < len(msg) else 0)
        s = s + w

    s = (s >> 16) + (s & 0xFFFF)
    s = s + (s >> 16)
    s = ~s & 0xFFFF  # Complement and mask to 16 bit
    return s

class RateLimiter:
    def __init__(self, max_rate):
        self.max_rate = max_rate
        self.timestamps = []

    def allow(self):
        current_time = time()
        self.timestamps = [t for t in self.timestamps if current_time - t < 1]

        if len(self.timestamps) < self.max_rate:
            self.timestamps.append(current_time)
            return True
        else:
            return False

rate_limiter = RateLimiter(100)  # Allow up to 100 logs per second

if rate_limiter.allow():
    logger.info("Log this packet")
else:
    logger.warning("Rate limit exceeded, dropping packet")

parser = argparse.ArgumentParser(description="Network Packet Sniffer")
parser.add_argument("--protocol", help="Specify protocol to capture", choices=['tcp', 'udp', 'icmp', 'arp'])
parser.add_argument("--src-ip", help="Filter by source IP")
args = parser.parse_args()

def packet_filter(ip_header):  
    if args.protocol and ip_header.protocol_map[ip_header.protocol_num].lower() != args.protocol:
        return False
    if args.src_ip and ip_header.src_address != args.src_ip:
        return False
    return True

def process_packet(raw_buffer):
    try:
        ip_header = IP(raw_buffer[:20])
        if packet_filter(ip_header):  
            if ip_header.protocol_num == 1:  # ICMP
                icmp_header = raw_buffer[ip_header.ihl * 4 : ip_header.ihl * 4 + 4]
                icmp_type, icmp_code, _, _ = struct.unpack("!BBHH", icmp_header)
                logger.info(f"Protocol: ICMP (type={icmp_type}, code={icmp_code}) {ip_header.src_address} -> {ip_header.dst_address}")
            elif ip_header.protocol_num == 6:  # TCP
                tcp_header = raw_buffer[ip_header.ihl * 4 : ip_header.ihl * 4 + 20]
                tcp_header_unpacked = struct.unpack("!HHLLBBHHH", tcp_header)
                src_port = tcp_header_unpacked[0]
                dst_port = tcp_header_unpacked[1]
                logger.info(f"Protocol: TCP {ip_header.src_address}:{src_port} -> {ip_header.dst_address}:{dst_port}")
            elif ip_header.protocol_num == 17:  # UDP
                udp_header = raw_buffer[ip_header.ihl * 4 : ip_header.ihl * 4 + 8]
                udp_header_unpacked = struct.unpack("!HHHH", udp_header)
                src_port = udp_header_unpacked[0]
                dst_port = udp_header_unpacked[1]
                logger.info(f"Protocol: UDP {ip_header.src_address}:{src_port} -> {ip_header.dst_address}:{dst_port}")

    except Exception as e:
        logger.error(f"Error processing packet: {e}")

def packet_capture_thread(sniffer, stop_event):
    while not stop_event.is_set():
        try:
            raw_buffer = sniffer.recvfrom(65565)[0]
            ip_header = IP(raw_buffer[0:20])
            if packet_filter(ip_header):
                process_packet(raw_buffer)
        except socket.error as e:
            if stop_event.is_set():
                break  # Exit loop if interrupted
            logging.error(f"Socket error: {e}")
            break  # Exit loop on socket error
        except KeyboardInterrupt:
            break  # Exit loop on Ctrl+C


def main():
    socket_protocol = socket.IPPROTO_IP if os.name == "nt" else socket.IPPROTO_ICMP
    stop_event = threading.Event()  # Define stop_event

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol) as sniffer:
            sniffer.bind((host, 0))
            sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            if os.name == "nt":
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
            threads = []
            for _ in range(10):  # Adjust the number of threads as needed
                thread = threading.Thread(target=packet_capture_thread, args=(sniffer, stop_event))
                thread.daemon = True  # Allow the main thread to exit even if these are running
                thread.start()
                threads.append(thread)

            try:
                while True:
                    sleep(1)  # Sleep for 1 second to allow threads to run
                    try:
                        raw_buffer, _ = sniffer.recvfrom(65565)

                        # Calculate IP Checksum
                        ip_header_len = (raw_buffer[0] & 0xF) * 4
                        ip_header_bytes = raw_buffer[:ip_header_len]
                        calculated_checksum = checksum(ip_header_bytes)
                        ip_header = IP(raw_buffer[0:20])
                        stored_checksum = socket.ntohs(ip_header.sum)

                        if calculated_checksum != stored_checksum:
                            logging.warning("Invalid IP checksum. Dropping packet.")
                            continue  # Skip to the next packet
                            
                        if len(raw_buffer) >= ip_header.ihl * 4:
                            # Protocol-specific parsing (ICMP, TCP, UDP)
                            if ip_header.protocol_num == 1:  # ICMP
                                icmp_header = raw_buffer[ip_header.ihl * 4 : ip_header.ihl * 4 + 4]
                                icmp_type, icmp_code, _, _ = struct.unpack("!BBHH", icmp_header)
                                logging.info(f"Protocol: ICMP (type={icmp_type}, code={icmp_code}) {ip_header.src_address} -> {ip_header.dst_address}")
                            elif ip_header.protocol_num == 6:  # TCP
                                tcp_header = raw_buffer[ip_header.ihl * 4 : ip_header.ihl * 4 + 20]
                                tcp_header_unpacked = struct.unpack("!HHLLBBHHH", tcp_header)
                                src_port = tcp_header_unpacked[0]
                                dst_port = tcp_header_unpacked[1]
                                logging.info(f"Protocol: TCP {ip_header.src_address}:{src_port} -> {ip_header.dst_address}:{dst_port}")
                            elif ip_header.protocol_num == 17:  # UDP
                                udp_header = raw_buffer[ip_header.ihl * 4 : ip_header.ihl * 4 + 8]
                                udp_header_unpacked = struct.unpack("!HHHH", udp_header)
                                src_port = udp_header_unpacked[0]
                                dst_port = udp_header_unpacked[1]
                                if src_port == 53 or dst_port == 53:
                                    logging.info(f"Protocol: DNS (UDP) {ip_header.src_address}:{src_port} -> {ip_header.dst_address}:{dst_port}")
                                else:
                                    logging.info(f"Protocol: UDP {ip_header.src_address}:{src_port} -> {ip_header.dst_address}:{dst_port}")

                    except socket.error as e:
                        logging.error(f"Socket error: {e}")
                    except KeyboardInterrupt:
                        logging.info("Sniffer stopped by user (Ctrl+C).")
                        break
                    except Exception as e:
                        logging.error(f"General error: {e}")

            except KeyboardInterrupt:
                logger.info("Interrupted by user. Exiting...")
                stop_event.set()  # Signal threads to stop

            for thread in threads:
                thread.join()  # Wait for all threads to finish

    finally:
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        else:
            logger.info("Exiting sniffer...")

if __name__ == "__main__":
    main()
