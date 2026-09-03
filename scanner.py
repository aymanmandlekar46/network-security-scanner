import nmap

target = input("Enter your IP address: ")

scanner = nmap.PortScanner()

print("\nScanning...")
scanner.scan(target, arguments="-sV")

for host in scanner.all_hosts():
    print(f"\nHost: {host}")
    print(f"Status: {scanner[host].state()}")

    for protocol in scanner[host].all_protocols():
        for port in scanner[host][protocol]:
            service = scanner[host][protocol][port]

            print(
                f"Port: {port} | "
                f"State: {service['state']} | "
                f"Service: {service.get('name', 'unknown')} | "
                f"Version: {service.get('version', 'unknown')}"
            )