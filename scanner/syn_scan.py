from scapy.all import sr1, send
from scapy.layers.inet import IP, TCP, ICMP
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(target, port):
    pkt = IP(dst=target)/TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=1, verbose=0)
    
    if resp is None:
        return {"port": port, "state": "filtered or no response"}
    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
            send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=0)
            return {"port": port, "state": "open"}
        elif resp.getlayer(TCP).flags == 0x14:  # RST
            return {"port": port, "state": "closed"}
    elif resp.haslayer(ICMP):
        if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
            return {"port": port, "state": "filtered"}

    return {"port": port, "state": "unknown"}

def scan(target, max_workers=100):
    print("Iniciando escaneo SYN...")
    scan_results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_port, target, port) for port in range(1, 65536)]
        for future in as_completed(futures):
            result = future.result()
            scan_results.append(result)

    return scan_results
