# https://github.com/nvinay123/Intrusion-Detection-System
# Import necessary libraries and modules
import threading
import time
from flask import Flask, render_template, jsonify, request, abort
import smtplib
from email.message import EmailMessage
import psutil
import jwt  # For JWT-based authentication
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key' 

# Global variables to store metrics
cpu_usage = []
memory_usage = []
anomalies = []
timestamps = []  # New list to store timestamps

# Global flag to stop threads
stop_threads = False

# RSA Key Pair Generation for Digital Signature
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Define SystemSentinelAgent class to monitor system and detect anomalies
class SystemSentinelAgent(threading.Thread):
    def __init__(self):
        super().__init__()
        self.model = AnomalyDetectionModel()
        self.last_alert_time = 0

    # Thread run method
    def run(self):
        while not stop_threads:
            data = self.collect_data()  # Collect real data here
            if self.model.predict(data):  # Check for anomalies
                current_time = time.time()
                if current_time - self.last_alert_time > 60:  # Alert if enough time has passed
                    signed_message = self.create_signed_alert("Potential threat detected!")
                    self.alert_admin(signed_message)
                    print(f"Data collected: {data}")  # Debug statement
                    threat_detected, threat_type, severity_level = self.model.predict(data)  # Get threat type and severity
                    print(f"Threat detected: {threat_detected}, Type: {threat_type}, Severity: {severity_level}")  # Debug statement
                    if threat_detected:
                        anomalies.append((f"Potential threat detected", threat_type, severity_level))

                    anomalies.append((f"Potential threat detected", threat_type, severity_level))

                    anomalies.append((f"Potential threat detected", threat_type, severity_level))


                    self.last_alert_time = current_time
            time.sleep(1)

    # Collect system data (CPU and memory usage)
    def collect_data(self):
        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory().percent
        cpu_usage.append(cpu)
        memory_usage.append(memory)
        timestamps.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))  # Add timestamp
        if len(cpu_usage) > 100:  # Limit the length of the lists
            cpu_usage.pop(0)
            memory_usage.pop(0)
            timestamps.pop(0)  # Maintain the same length for timestamps
        return {'cpu': cpu, 'memory': memory, 'timestamp': timestamps[-1]}  # Return timestamp

    # Generate and sign an alert message
    def create_signed_alert(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message_to_sign = f"{message} at {timestamp}".encode()
        signature = private_key.sign(
            message_to_sign,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return f"{message} (Signature: {signature.hex()})"

    # Send alert to admin
    def alert_admin(self, signed_message):
        print(signed_message)
        send_email(signed_message)

# Function to send email
def send_email(message):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "sonivishwakarma022@gmail.com"
    receiver_email = "2022012007.sonivdn@student.xavier.ac.in"
    app_password = ""  # Use the App Password generated

    email = EmailMessage()
    email.set_content(message)
    email['Subject'] = 'IDS Alert'
    email['From'] = sender_email
    email['To'] = receiver_email

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, app_password)
        server.send_message(email)
        print("Email alert sent successfully!")
    except Exception as e:
        print("Failed to send email alert:", e)
    finally:
        server.quit()

# Define SystemFaultEvaluationAgent class to evaluate system faults
class SystemFaultEvaluationAgent(threading.Thread):
    def run(self):
        while not stop_threads:
            self.analyze_data()
            time.sleep(2)

    # Analyze collected data
    def analyze_data(self):
        print("Analyzing system data...")

# Define SystemReplicationAgent class to manage system replication and recovery
class SystemReplicationAgent(threading.Thread):
    def run(self):
        while not stop_threads:
            self.manage_replication()
            time.sleep(3)

    # Manage replication and recovery processes
    def manage_replication(self):
        print("Managing replication and recovery...")

# Define ProfileDatabase class to update the profile database
class ProfileDatabase:
    def update_database(self, data):
        print("Updating profile database with new data.")

# Define LSIA (Local System Intelligence Agent) class to manage agents
class LSIA:
    def start_agents(self):
        print("Starting all agents...")
        agents = [SystemSentinelAgent(), SystemFaultEvaluationAgent(), SystemReplicationAgent()]
        for agent in agents:
            agent.start()

    def stop_agents(self):
        global stop_threads
        stop_threads = True
        print("Stopping all agents...")

# Define AnomalyDetectionModel class to predict anomalies
class AnomalyDetectionModel:
    def predict(self, data): 
        # Add logic to determine threat type and severity
        threat_type = "High" if data['cpu'] > 20.0 else "High" if data['memory'] > 80.0 else "None"
        severity_level = "High" if data['cpu'] > 20.0 or data['memory'] > 80.0 else "Low"

        cpu_threshold = 20.0  # Updated threshold for CPU usage
        memory_threshold = 80.0  # Updated threshold for memory usage

        if data['cpu'] > cpu_threshold or data['memory'] > memory_threshold:
            return True, threat_type, severity_level  # Return threat type and severity level

        return False

# Define route for dashboard with logging
@app.route('/')
def dashboard():
    print("Handling dashboard request")
    return render_template('ids_system.html')

# Define route for metrics with detailed logging
@app.route('/metrics')
def metrics():
    print("Handling metrics request")
    anomaly_info = anomalies.pop(0) if anomalies else ("No anomalies detected", "None", "Low")  # Include threat type and severity

    return jsonify({
        'cpu': cpu_usage[-1] if cpu_usage else 0,
        'memory': memory_usage[-1] if memory_usage else 0,
        'timestamp': timestamps[-1] if timestamps else None,
        'anomaly': anomaly_info[0],  # Display anomaly status
        'threat_type': anomaly_info[1],  # Display threat type
        'severity_level': anomaly_info[2]  # Display severity level

    })

# Main function with startup logging
def main():
    print("Starting Flask application...")
    lsia = LSIA()
    lsia.start_agents()
    
    try:
        print("Running Flask app on http://0.0.0.0:5001")
        app.run(host='0.0.0.0', port=5001)

    except Exception as e:
        print("Error running Flask app:", e)
    finally:
        print("Stopping agents...")
        lsia.stop_agents()

# Run the main function when the script is executed
if __name__ == "__main__":
    main()
