from flask import Flask, render_template, request, jsonify, send_from_directory
import nmap
import os
import json
from datetime import datetime
import subprocess

app = Flask(__name__)
SCANS_DIR = 'scans'

if not os.path.exists(SCANS_DIR):
    os.makedirs(SCANS_DIR)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target')
    scan_type = request.form.get('scan_type', '-sV')
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments=f'{scan_type} --script vulners')

        scan_results = nm._scan_result

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'scan_{timestamp}.json'
        filepath = os.path.join(SCANS_DIR, filename)
        with open(filepath, 'w') as f:
            json.dump(scan_results, f, indent=4)

        return jsonify({
            'status': 'success',
            'results': scan_results,
            'download_link': f'/download/{filename}'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/amass_scan', methods=['POST'])
def amass_scan():
    target = request.form.get('target')
    try:
        result = subprocess.run(['amass', 'enum', '-d', target], capture_output=True, text=True)

        if result.returncode != 0:
            return jsonify({
                'status': 'error',
                'message': result.stderr
            })

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'amass_scan_{timestamp}.txt'
        filepath = os.path.join(SCANS_DIR, filename)
        with open(filepath, 'w') as f:
            f.write(result.stdout)

        return jsonify({
            'status': 'success',
            'download_link': f'/download/{filename}'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/nikto_scan', methods=['POST'])
def nikto_scan():
    target = request.form.get('target')
    try:
        result = subprocess.run(['nikto', '-h', target], capture_output=True, text=True)

        if result.returncode != 0:
            return jsonify({
                'status': 'error',
                'message': result.stderr
            })

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'nikto_scan_{timestamp}.txt'
        filepath = os.path.join(SCANS_DIR, filename)
        with open(filepath, 'w') as f:
            f.write(result.stdout)

        return jsonify({
            'status': 'success',
            'download_link': f'/download/{filename}'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(SCANS_DIR, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)