from scanner import syn_scan, os_detection, service_detection, firewall_detection, vulnerability_analysis, report_generation

def main():
    target = input("Ingrese la dirección IP objetivo: ")

    # Escaneo SYN
    syn_results = syn_scan.scan(target)

    # Detección de SO
    os_info = os_detection.detect_os(target)

    # Detección de versiones de servicios
    services = service_detection.detect_services(syn_results)

    # Detección de Firewalls/IDS
    firewall_info = firewall_detection.detect_firewall(target)

    # Análisis de vulnerabilidades
    vulnerabilities = vulnerability_analysis.analyze_vulnerabilities(services)

    # Generación de informes
    report_generation.generate_report(target, syn_results, os_info, services, firewall_info, vulnerabilities)

if __name__ == "__main__":
    main()
