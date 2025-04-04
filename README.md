# Network-Scanner
Built a web-based Network Scanner with three modules: Port Scanner, LAN Scanner, and Intrusion Detection.
Designed a responsive UI using Flask for the backend, HTML/CSS and JavaScript for the frontend enabling real-time
scan configuration and dynamic result display.

**1. Desktop:**
![Screenshot 2025-04-04 221329](https://github.com/user-attachments/assets/50506b43-1f76-40ed-85f0-778adee908a4)


**2. Port Scanner:**
Developed a web-based Port Scanner using Python and Flask, enabling users to scan target IP addresses with customizable scan types (light, deep, or custom port range).

Implemented multi-threaded socket programming to efficiently detect open, closed, or filtered TCP ports with detailed banner grabbing for service detection.

Integrated optional features like OS detection using Nmap and network path tracing via Traceroute for advanced network analysis.

Designed an intuitive frontend interface using HTML templates to facilitate real-time scanning and display results in a user-friendly format.

Employed Queue and threading to handle up to 200 concurrent connections, optimizing scanning speed and responsiveness.

![Screenshot 2025-04-04 221534](https://github.com/user-attachments/assets/3a5ceae6-37cc-47df-8cca-ad919ab4fe2b)


![Screenshot 2025-04-04 221730](https://github.com/user-attachments/assets/8e53db87-08a7-4499-b0c7-69e1247740a4)


![traceroute](https://github.com/user-attachments/assets/250cbc82-48a9-414f-ae5d-398ffd7161c7)


**3. LAN Scanner:**
LAN vulnerability scanner can detect open ports and potential security issues across a specified subnet.

Implemented multithreaded scanning using concurrent.futures for faster performance across large networks.

Integrated a simulated vulnerability database to identify risks associated with open services (e.g., FTP, Telnet, SMB, SQL).

Used Python’s socket and ipaddress libraries for real-time port and service detection within given IP and port ranges.

Designed a responsive UI with Flask (backend) and JavaScript (frontend) to accept user input and display scan results in JSON format.
![Screenshot 2025-04-04 223740](https://github.com/user-attachments/assets/d5e0f288-37c9-4504-93ec-0600d26d7e80)


**5. Intrusion Detection:** 
Added a lightweight Intrusion Detection system to identify unauthorized or suspicious activity on the network.
![Screenshot 2025-04-04 223647](https://github.com/user-attachments/assets/e269fa66-aa7d-4011-b977-75f5b44fadbc)






