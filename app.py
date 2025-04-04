from flask import Flask, render_template
from portscanner import scan as port_scan, port_index  
from lan import scan1 as lan_scan, lan_index  

app = Flask(__name__)

@app.route('/')
def index(): 
    return render_template('index.html')

# Route for the main dashboard (Port Scanner)
app.add_url_rule("/portscanner", "port_index", port_index)  

# API Route for Port Scanning
app.add_url_rule("/portscanner/scan", "port_scan", port_scan, methods=['POST'])  

# Route for LAN Scanner page
app.add_url_rule("/lan", "lan_index", lan_index)  

# API Route for LAN Scanning
app.add_url_rule("/lan/scan", "lan_scan", lan_scan, methods=['POST'])  

if __name__ == "__main__":
    app.run(debug=True, port=5000)  # Run the main app on Port 5000
