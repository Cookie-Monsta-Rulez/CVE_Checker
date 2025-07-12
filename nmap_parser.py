import xml.etree.ElementTree as ET

# ---------------- NMAP PARSER ----------------
def parse_nmap_services(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    services = []
    for host in root.findall(".//host"):
        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                break
        for port in host.findall(".//port"):
            service = port.find("service")
            if service is not None and ip:
                product = service.get("product", "").lower()
                version_ = service.get("version", "")
                if product and version_:
                    services.append({
                        "ip": ip,
                        "port": port.get("portid"),
                        "product": product,
                        "version": version_,
                    })
    return services