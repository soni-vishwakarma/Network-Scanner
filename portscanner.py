from flask import Flask,render_template, request
import threading
from socket import *
from queue import Queue 
import nmap
import subprocess

N_THREADS = 200  
queue = Queue()
print_lock = threading.Lock()
results = []

app = Flask(__name__)
def grab_banner(conn_skt):
    try:
        conn_skt.send(b'HEAD / HTTP/1.1\r\n\r\n')
        return conn_skt.recv(1024).decode().strip()
    except:
        return 'Banner not available'

def conScan(tgtHost, tgtPort, detectService):
    try:
        conn_skt = socket(AF_INET, SOCK_STREAM)
        conn_skt.connect((tgtHost, tgtPort))
        conn_skt.settimeout(0.5)  
        banner = grab_banner(conn_skt) if detectService else ''
        with print_lock:
            result = f'[+] {tgtPort}/tcp open: {banner}'
            results.append(result)
        conn_skt.close()
    except:
        with print_lock:
            result = f'[-] {tgtPort}/tcp closed'
            results.append(result)

def worker(tgtHost, detectService):
    while not queue.empty():
        tgtPort = queue.get()
        conScan(tgtHost, tgtPort, detectService)
        queue.task_done()

def portScan(tgtHost, tgtPorts, detectService):
    global results
    results = []
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        results.append(f'[-] Cannot resolve {tgtHost}')
        return results
    try:
        tgtName = gethostbyaddr(tgtIP)
        results.append(f'\n[+] Scan result of: {tgtName[0]}')
    except:
        results.append(f'\n[+] Scan result of: {tgtIP}')

    setdefaulttimeout(0.5)  

    for tgtPort in tgtPorts:
        queue.put(tgtPort)

    for _ in range(N_THREADS):
        thread = threading.Thread(target=worker, args=(tgtHost, detectService))
        thread.daemon = True
        thread.start()

    queue.join()
    return results

def detect_os(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments='-O')
        os_results = []
        for host in nm.all_hosts():
            os_results.append(f"Host : {host} ({nm[host].hostname()})")
            os_results.append(f"State : {nm[host].state()}")

            if 'osclass' in nm[host]:
                for osclass in nm[host]['osclass']:
                    os_results.append(f"OS Type : {osclass['type']}")
                    os_results.append(f"OS Vendor : {osclass['vendor']}")
                    os_results.append(f"OS Family : {osclass['osfamily']}")
                    os_results.append(f"OS Generation : {osclass['osgen']}")
                    os_results.append(f"OS Accuracy : {osclass['accuracy']}%")
        return os_results
    except Exception as e:
        return [f"Operating System: OS Detection Failed ({str(e)})"]

def trace_route(target):
    try:
        result = subprocess.check_output(['tracert', target], universal_newlines=True)
        return result.split('\n')
    except Exception as e:
        return [f"Traceroute: Traceroute Failed ({str(e)})"]
    
@app.route('/portscanner')
def port_index():  
    return render_template('portscanner.html')

@app.route('/portscanner/scan',methods=['POST'])
def scan():
    target = request.form['target']
    scan_type = request.form['scanType']
    detect_service = 'detectService' in request.form  
    detect_os_flag = 'detectOS' in request.form  
    trace_route_flag = 'traceRoute' in request.form  

    if scan_type == 'lightScan':  
        target_ports = list(range(1, 1025))  
    elif scan_type == 'deepScan':  
        target_ports = list(range(1, 65536))  
    elif scan_type == 'range':  
        port_range = request.form['portRange']
        start_port, end_port = map(int, port_range.split('-'))
        target_ports = list(range(start_port, end_port + 1))  

    results = portScan(target, target_ports, detect_service)

    if detect_os_flag:
        os_info = detect_os(target)
        results.append("Operating System Info:")
        results.extend(os_info)

    if trace_route_flag:
        trace_info = trace_route(target)
        results.append("Traceroute Results:")
        results.extend(trace_info)

    return '\n'.join(results)
