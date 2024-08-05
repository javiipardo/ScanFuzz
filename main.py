from scanner import syn_scan, os_detection, service_detection, firewall_detection, vulnerability_analysis, report_generation

def main():
    target = input("Ingrese la dirección IP objetivo: ")

    # Escaneo SYN
    syn_results = syn_scan.scan(target)
    
    # Mostrar resultados del escaneo SYN
    print("Puertos escaneados:")
    for result in syn_results:
        print(result)

    # Puedes continuar con otras funciones aquí
    # os_info = os_detection.detect_os(target)
    # services = service_detection.detect_services(syn_results)
    # firewall_info = firewall_detection.detect_firewall(target)
    # vulnerabilities = vulnerability_analysis.analyze_vulnerabilities(services)
    # report_generation.generate_report(target, syn_results, os_info, services, firewall_info, vulnerabilities)

if __name__ == "__main__":
    main()
