#!/usr/bin/env python3

"""
ScanFuzz v1.0

Escáner de puertos sigiloso y fuzzing de directorios diseñado para CTFs y pruebas de penetración.
Desarrollado por javiipardo en GitHub: https://github.com/javiipardo

Funciones principales:
- Escaneo sigiloso de puertos con SYN (Half-Open Scan)
- Detección del sistema operativo a partir del TTL de respuestas TCP
- Fuzzing de directorios y recursos web utilizando una wordlist
- Almacenamiento de resultados en formato JSON
"""

from scapy.all import IP, TCP, sr1
import argparse
import socket
from colorama import Fore, Style, init
import json
import aiohttp
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import signal
import sys
import threading

init(autoreset=True)

stop_event = threading.Event()

def custom_thread_exception_handler(args):
    print(Fore.RED + f"[x] Excepción en hilo: {args.exc_type}, {args.exc_value}")

threading.excepthook = custom_thread_exception_handler

start_time = time.time()

def tiempo_transcurrido():
    """Calcula el tiempo transcurrido desde que inició el escaneo."""
    elapsed = time.time() - start_time
    return f"[Tiempo: {elapsed:.2f}s]"

def validar_puertos(puertos):
    """Valida y convierte una lista de puertos proporcionada como cadena en una lista de enteros."""
    try:
        puertos_list = [int(p) for p in puertos.split(",")]
        for puerto in puertos_list:
            if puerto < 1 or puerto > 65535:
                raise ValueError(f"Puerto fuera de rango: {puerto}")
        return puertos_list
    except ValueError as e:
        print(Fore.RED + f"[x] Error: {e}")
        sys.exit(1)

def escanear_puertos_syn(host, puertos, max_threads=10, delay=0, filtro=None):
    """Escanea múltiples puertos en paralelo usando SYN scan."""
    print(Fore.GREEN + "[!] Iniciando escaneo de puertos sigiloso...\n")
    resultados = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(escanear_puerto_syn, host, puerto, 1, delay): puerto for puerto in puertos}
        for future in as_completed(futures):
            if stop_event.is_set():
                break
            puerto = futures[future]
            try:
                resultado, estado = future.result()
                if filtro is None or estado == filtro:
                    servicio = obtener_servicio(resultado)
                    if estado == "open":
                        print(Fore.YELLOW + f"[✔] Puerto abierto: {resultado} ({servicio})")
                    elif estado == "closed":
                        print(Fore.RED + f"[x] Puerto cerrado: {resultado} ({servicio})")
                    elif estado == "filtered":
                        print(Fore.BLUE + f"[?] Puerto filtrado: {resultado} ({servicio})")
                    resultados.append((resultado, estado))
            except Exception as e:
                print(Fore.RED + f"[x] Error al escanear el puerto {puerto}: {e}")
        for future in futures:
            future.cancel()
    print(Fore.GREEN + "\n[✔] Escaneo de puertos completado.")
    print(Fore.CYAN + tiempo_transcurrido() + "\n")
    return resultados

def escanear_puerto_syn(host, puerto, timeout=1, delay=0):
    """Realiza un escaneo SYN (Half-Open Scan) en un puerto específico."""
    try:
        if stop_event.is_set():
            return None
        time.sleep(delay)
        paquete = IP(dst=host) / TCP(dport=puerto, flags="S")
        respuesta = sr1(paquete, timeout=timeout, verbose=0)
        if respuesta and respuesta.haslayer(TCP):
            if respuesta.getlayer(TCP).flags == 0x12:
                return puerto, "open"
            elif respuesta.getlayer(TCP).flags == 0x14:
                return puerto, "closed"
        return puerto, "filtered"
    except Exception as e:
        print(Fore.RED + f"[x] Error al escanear el puerto {puerto}: {e}")
    return puerto, "error"

def obtener_os(host):
    """Intenta detectar el sistema operativo basado en el TTL de la respuesta TCP en el puerto 80."""
    try:
        paquete = IP(dst=host) / TCP(dport=80, flags="S")
        respuesta = sr1(paquete, timeout=2, verbose=0)
        if respuesta and respuesta.haslayer(TCP):
            ttl = respuesta[IP].ttl
            if ttl <= 64:
                return "Linux"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Desconocido"
        return "No se pudo detectar el OS"
    except Exception as e:
        print(Fore.RED + f"[x] Error al detectar el sistema operativo: {e}")
        return "Desconocido"

def obtener_servicio(puerto):
    """Obtiene el nombre del servicio asociado a un puerto específico."""
    try:
        return socket.getservbyport(puerto)
    except OSError:
        return "Desconocido"

async def fuzzear_directorio(session, url, palabra, delay=0, timeout=5, filtro=None):
    """Realiza una petición HTTP a una URL construida con una palabra clave de la wordlist."""
    if stop_event.is_set():
        return None
    if not palabra or palabra.startswith("#"):
        return None
    full_url = f"{url}/{palabra}"
    try:
        await asyncio.sleep(delay)
        async with session.get(full_url, timeout=timeout) as response:
            if filtro is None or response.status == filtro:
                if response.status != 404:
                    print(Fore.YELLOW + f"[✔] {full_url} - Código: {response.status}")
                    return {"url": full_url, "status": response.status}
    except asyncio.TimeoutError:
        print(Fore.RED + f"[x] Timeout en {full_url}")
    except Exception as e:
        print(Fore.RED + f"[x] Error en {full_url}: {e}")
    return None

async def fuzzing(url, wordlist, max_concurrent=20, delay=0, block_size=100, filtro=None):
    """Realiza fuzzing de directorios y recursos web en paralelo utilizando una wordlist."""
    print(Fore.GREEN + "[!] Iniciando fuzzing de directorios...\n")
    encontrados = []
    connector = aiohttp.TCPConnector(limit_per_host=max_concurrent)
    async with aiohttp.ClientSession(connector=connector) as session:
        for i in range(0, len(wordlist), block_size):
            if stop_event.is_set():
                break
            block = wordlist[i:i + block_size]
            tasks = [fuzzear_directorio(session, url, palabra.strip(), delay, filtro=filtro) for palabra in block]
            results = await asyncio.gather(*tasks)
            for res in results:
                if res:
                    encontrados.append(res)
    print(Fore.GREEN + "\n[✔] Fuzzing completado.")
    print(Fore.CYAN + tiempo_transcurrido() + "\n")
    return encontrados

def guardar_resultados(host, puertos_abiertos, fuzz_results):
    """Guarda los resultados del escaneo en un archivo JSON."""
    try:
        data = {
            "host": host,
            "puertos_abiertos": puertos_abiertos,
            "fuzzing": fuzz_results
        }
        with open(f"{host}_resultados.json", "w") as f:
            json.dump(data, f, indent=4)
        print(Fore.GREEN + f"[✔] Resultados guardados en {host}_resultados.json\n")
    except Exception as e:
        print(Fore.RED + f"[x] Error al guardar los resultados: {e}\n")

def signal_handler(sig, frame):
    """Maneja la interrupción de Ctrl+C y detiene el escaneo."""   
    stop_event.set()
    print(Fore.RED + "[x] Escaneo detenido por el usuario.\n")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def main():
    """Función principal que coordina el escaneo de puertos y el fuzzing."""
    print(Fore.CYAN + """
    ==========================================
    |            ScanFuzz v1.0               |
    |  Desarrollado por javiipardo en GitHub |
    |  https://github.com/javiipardo         |
    ==========================================
    """)

    parser = argparse.ArgumentParser(
        description="ScanFuzz: Escáner de puertos sigiloso y fuzzing para CTFs",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("host", help="IP o dominio a escanear")
    parser.add_argument("-p", "--puertos", type=str, default="80,443,22,21,8080,3306,25,110,143,53,123,135,139,445,993,995,1723,3306,3389,5900,8080,8443,8888",
                        help="Lista de puertos a escanear o -p- para todos los puertos")
    parser.add_argument("--open", action="store_true", help="Mostrar solo puertos abiertos")
    parser.add_argument("--closed", action="store_true", help="Mostrar solo puertos cerrados")
    parser.add_argument("--filtered", action="store_true", help="Mostrar solo puertos filtrados")
    parser.add_argument("-w", "--wordlist", type=str, default="rockyou.txt", help="Lista de palabras para fuzzing")
    parser.add_argument("--status-code", type=int, help="Filtrar fuzzing por código de respuesta HTTP")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Número máximo de hilos para el escaneo (máximo 10)", choices=range(1, 11))
    parser.add_argument("-b", "--block-size", type=int, default=100, help="Tamaño del bloque para procesar la wordlist")
    parser.add_argument("--min-rate", type=int, default=25, help="Velocidad mínima de envío de paquetes por segundo", choices=range(1, 5001))
    parser.add_argument("--no-dns", action="store_true", help="No realizar resolución DNS")
    args = parser.parse_args()

    computed_delay = 1.0 / args.min_rate

    if args.puertos == "-":
        args.puertos = list(range(1, 65536))
    else:
        args.puertos = validar_puertos(args.puertos)

    if not args.no_dns:
        try:
            args.host = socket.gethostbyname(args.host)
        except socket.gaierror as e:
            print(Fore.RED + f"[x] Error al resolver el host: {e}")
            sys.exit(1)

    filtro_puertos = None
    if args.open:
        filtro_puertos = "open"
    elif args.closed:
        filtro_puertos = "closed"
    elif args.filtered:
        filtro_puertos = "filtered"

    os_detectado = obtener_os(args.host)
    print(Fore.GREEN + f"[✔] Sistema operativo detectado: {os_detectado}\n")

    puertos_abiertos = escanear_puertos_syn(args.host, args.puertos, max_threads=args.threads,
                                             delay=computed_delay, filtro=filtro_puertos)

    fuzz_results = []
    if 80 in [p[0] for p in puertos_abiertos if p[1] == "open"] or 443 in [p[0] for p in puertos_abiertos if p[1] == "open"] or 8443 in [p[0] for p in puertos_abiertos if p[1] == "open"]:
        url = f"https://{args.host}" if 443 in [p[0] for p in puertos_abiertos if p[1] == "open"] else f"http://{args.host}"
        try:
            with open(args.wordlist, "r", encoding="ISO-8859-1") as f:
                wordlist = f.readlines()
            fuzz_results = asyncio.run(fuzzing(url, wordlist, max_concurrent=20,
                                                delay=computed_delay, block_size=args.block_size, filtro=args.status_code))
        except FileNotFoundError:
            print(Fore.RED + "[x] No se encontró el archivo de wordlist.\n")
            

    guardar_resultados(args.host, puertos_abiertos, fuzz_results)

if __name__ == "__main__":
    main()
    