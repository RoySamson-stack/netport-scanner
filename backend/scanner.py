import nmap

def scan_ports(target, ports):
    scanner = nmap.PortScanner()
    scanner.scan(target, ports)
    return scanner.csv()