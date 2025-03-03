import re
from flask import Flask, request, jsonify
import subprocess
import logging

app = Flask(__name__)

# Logging setup
logging.basicConfig(filename='/var/log/blocked_ips.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to validate IPv4 addresses
def is_valid_ip(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if not pattern.match(ip):
        return False
    return all(0 <= int(octet) <= 255 for octet in ip.split("."))

@app.route('/block_ip', methods=['POST'])
def block_ip():
    try:
        # Enforce JSON Content-Type
        if request.content_type != 'application/json':
            return jsonify({"error": "Unsupported Media Type. Use 'Content-Type: application/json'"}), 415

        data = request.get_json()
        if not data:
            return jsonify({"error": "Empty JSON payload"}), 400

        ip = data.get("ip")

        if not ip or not is_valid_ip(ip):
            return jsonify({"error": "Invalid IP address"}), 400

        # Log received IP for debugging
        logging.info(f"Received request to block IP: {ip}")

        # Run UFW command and capture output
        result = subprocess.run(
            ["sudo", "-n", "ufw", "deny", "from", ip],
            capture_output=True, text=True, check=True
        )

        # Log the blocked IP and output
        logging.info(f"Blocked IP: {ip} - {result.stdout}")

        return jsonify({"status": "success", "message": f"Blocked {ip}", "output": result.stdout}), 200

    except subprocess.CalledProcessError as e:
        error_message = f"Command failed: {e.stderr}"
        logging.error(error_message)
        return jsonify({"error": error_message}), 500

    except Exception as e:
        error_message = f"Unexpected error: {str(e)}"
        logging.error(error_message)
        return jsonify({"error": error_message}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)