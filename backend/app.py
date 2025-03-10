from flask import Flask, request, jsonify
import os
from scanner import scan_ports

app = Flask(__name__)

RESULTS_DIR = "results"
if not os.path.exists(RESULTS_DIR):
    os.makedirs(RESULTS_DIR)

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    target = data.get('target')
    ports = data.get('ports', '1-1000') 

    if not target:
        return jsonify({"error": "Target is required"}), 400

    scan_results = scan_ports(target, ports)

    result_file = os.path.join(RESULTS_DIR, f"{target}_scan.txt")
    with open(result_file, 'w') as f:
        f.write(scan_results)

    return jsonify({"message": "Scan completed", "file": result_file})

if __name__ == '__main__':
    app.run(debug=True)