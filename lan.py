from flask import Flask, render_template, request, jsonify
import socket
import concurrent.futures
import ipaddress

app = Flask(__name__)

def check_vulnerabilities(port, service_name):
    vulnerabilities = {
        21: "Anonymous FTP login possible (simulated)",
        22: "Weak SSH key exchange algorithms (simulated)",
        23: "Telnet service running (insecure)",
        80: "HTTP without HTTPS (simulated)",
        443: "Potentially outdated SSL/TLS version (simulated)",
        445: "SMB vulnerabilities (simulated)",
        135: "Potential MSRPC vulnerabilities (simulated)",
        139: "NetBIOS vulnerabilities (simulated)",
        3389: "RDP weak encryption or misconfiguration (simulated)",
        1433: "MSSQL default credentials or unpatched vulnerabilities (simulated)",
        3306: "MySQL default credentials or unpatched vulnerabilities (simulated)",
        5432: "PostgreSQL default credentials or unpatched vulnerabilities (simulated)",
        53: "DNS zone transfer possible or vulnerable DNS server (simulated)",
        25: "Open SMTP relay or unpatched vulnerabilities (simulated)",
        110: "POP3 weak authentication or unpatched vulnerabilities (simulated)",
        143: "IMAP weak authentication or unpatched vulnerabilities (simulated)",
        161: "SNMP default community strings or unpatched vulnerabilities (simulated)"
    }
    return [vulnerabilities[port]] if port in vulnerabilities else []

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Increased timeout
        result = sock.connect_ex((ip, port))
        if result == 0:
            try:
                service_name = socket.getservbyport(port)
            except OSError:
                service_name = "Unknown"
            vulnerabilities = check_vulnerabilities(port, service_name)
            formatted_result = {
                "host": ip,
                "port": port,
                "service": service_name,
                "status": "Open",
                "vulnerabilities": vulnerabilities if vulnerabilities else ["None"]
            }
            return formatted_result
        sock.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

def scan_network(network_prefix, start_port, end_port):
    results = []
    try:
        network = ipaddress.ip_network(network_prefix, strict=False)
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_scan = {
                executor.submit(scan_port, str(ip), port): (str(ip), port)
                for ip in network for port in range(start_port, end_port + 1)
            }
            for future in concurrent.futures.as_completed(future_to_scan):
                result = future.result()
                if result:
                    results.append(result)
    except Exception as e:
        return [{"error": str(e)}]
    return results

@app.route('/lan')
def lan_index():
    return render_template('lan.html')

@app.route('/lan/scan', methods=['POST'])
def scan1():
    data = request.json
    try:
        network_prefix = data.get('network_prefix', '')
        start_port = int(data.get('start_port', 0))
        end_port = int(data.get('end_port', 0))

        # Input validation
        ipaddress.ip_network(network_prefix, strict=False)
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError("Invalid port range")

        results = scan_network(network_prefix, start_port, end_port)
        return jsonify(results)
    except ValueError as ve:
        return jsonify({"error": str(ve)})
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred: " + str(e)})

