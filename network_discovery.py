import nmap

target = input("Enter your IP address: ")

scanner = nmap.PortScanner()

print("\nScanning services and versions...\n")

scanner.scan(target, arguments="-sV")

if target not in scanner.all_hosts():
    print("Host not found.")
else:
    print(f"Host: {target}")
    print(f"Status: {scanner[target].state()}")

    for protocol in scanner[target].all_protocols():
        for port in sorted(scanner[target][protocol]):
            service = scanner[target][protocol][port]

            print(
                f"Port: {port} | "
                f"State: {service.get('state', 'unknown')} | "
                f"Service: {service.get('name', 'unknown')} | "
                f"Version: {service.get('version', 'unknown')}"
            )