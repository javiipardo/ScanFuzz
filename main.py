from scanner.syn_scan import scan

def main():
    target = input("Ingrese la dirección IP objetivo: ")
    open_ports = scan(target)
    
    print("\nPuertos abiertos:")
    for port in open_ports:
        print(f"Port {port}")

if __name__ == "__main__":
    main()
