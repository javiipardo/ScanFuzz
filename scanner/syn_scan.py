from scapy.all import sr1, send
from scapy.layers.inet import IP, TCP, ICMP
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

def scan_port(target, port):
    pkt = IP(dst=target)/TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=1, verbose=0)
    
    if resp is None:
        return port, "filtered or no response"
    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
            send(IP(dst=target)/TCP(dport=port, flags="R"), verbose=0)
            return port, "open"
        elif resp.getlayer(TCP).flags == 0x14:  # RST
            return port, "closed"
    elif resp.haslayer(ICMP):
        if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
            return port, "filtered"

    return port, "unknown"

def scan(target, max_workers=100):
    print("Iniciando escaneo SYN...")
    total_ports = 65535
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, target, port): port for port in range(1, total_ports + 1)}
        with tqdm(total=total_ports) as pbar:
            for future in as_completed(futures):
                port, state = future.result()
                pbar.update(1)
                if state == "open":
                    open_ports.append(port)
                    print(f"Port {port}: {state}")

    return open_ports
