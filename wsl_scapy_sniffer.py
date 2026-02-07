#!/usr/bin/env python3

from scapy.all import *
import argparse
import socket
from datetime import datetime

def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except:
        print(f"[!] Не удалось резолвить {host}")
        return None

def packet_callback(packet):
    timestamp = datetime.now().strftime("%H:%M:%S")

    # DNS
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        qname = packet[DNSQR].qname.decode()
        print(f"[{timestamp}] DNS запрос: {qname}")

    # TCP
    if packet.haslayer(TCP) and packet.haslayer(IP):
        ip = packet[IP]
        tcp = packet[TCP]
        print(f"[{timestamp}] TCP {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport} Flags={tcp.flags}")

    # HTTP (только если без TLS)
    if packet.haslayer(Raw) and packet.haslayer(TCP):
        payload = packet[Raw].load
        if b"HTTP" in payload or b"GET" in payload or b"POST" in payload:
            try:
                print(f"\n[{timestamp}] HTTP данные:")
                print(payload.decode(errors="ignore")[:500])
                print("-" * 50)
            except:
                pass

def main():
    parser = argparse.ArgumentParser(description="WSL Scapy Traffic Analyzer")
    parser.add_argument("--host", help="Фильтр по домену или IP")
    parser.add_argument("--timeout", type=int, default=60, help="Время перехвата в секундах")
    parser.add_argument("--output", help="Сохранить pcap файл")
    args = parser.parse_args()

    iface = "eth0"
    bpf_filter = ""

    if args.host:
        ip = resolve_host(args.host)
        if ip:
            bpf_filter = f"host {ip}"
            print(f"[+] Фильтр по хосту: {args.host} ({ip})")

    print(f"[+] Начинаем перехват на интерфейсе {iface} на {args.timeout} сек...")
    
    packets = sniff(
        iface=iface,
        filter=bpf_filter,
        prn=packet_callback,
        timeout=args.timeout,
        store=True
    )

    print(f"\n[+] Перехвачено пакетов: {len(packets)}")

    if args.output:
        wrpcap(args.output, packets)
        print(f"[+] Сохранено в файл: {args.output}")

if __name__ == "__main__":
    main()

