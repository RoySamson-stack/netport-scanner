from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import nmap
import os
import json
from datetime import datetime
import pandas as pd
from functools import wraps
import subprocess

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here' 
app.config['SCANS_DIR'] = 'scans'
app.config['REPORTS_DIR'] = 'reports'

for directory in [app.config['SCANS_DIR'], app.config['REPORTS_DIR']]:
    if not os.path.exists(directory):
        os.makedirs(directory)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

users = {
    'admin': {
        'password': generate_password_hash('admin_password'),
        'role': 'admin'
    },
    'analyst': {
        'password': generate_password_hash('analyst_password'),
        'role': 'analyst'
    },
    'viewer': {
        'password': generate_password_hash('viewer_password'),
        'role': 'viewer'
    }
}

class User(UserMixin):
    def __init__(self, id, role):
        self.id = id
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id, users[user_id]['role'])
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            flash('Admin privileges required')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def analyst_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role not in ['admin', 'analyst']:
            flash('Analyst privileges required')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username in users and check_password_hash(users[username]['password'], password):
            user = User(username, users[username]['role'])
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    scans = get_available_scans()
    return render_template('dashboard.html', 
                          scans=scans, 
                          user_role=current_user.role)


@app.route('/scan', methods=['GET', 'POST'])
@analyst_required
def scan():
    if request.method == 'GET':
        return render_template('scan_form.html')

    target = request.form.get('target')
    scan_type = request.form.get('scan_type', '-sV')
    scan_name = request.form.get('scan_name', 'Unnamed Scan')
    module_name = request.form.get('module_name')

    recon_ng_command = ['recon-ng', '-w', 'target', '-m', module_name, '-t', target]
    subprocess.run(recon_ng_command)

    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments=f'{scan_type} --script vulners')

        scan_results = nm._scan_result

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'scan_{timestamp}.json'
        filepath = os.path.join(app.config['SCANS_DIR'], filename)

        scan_results['metadata'] = {
            'scan_name': scan_name,
            'timestamp': timestamp,
            'user': current_user.id,
            'target': target,
            'scan_type': scan_type,
            'recon_ng_module': module_name
        }

        with open(filepath, 'w') as f:
            json.dump(scan_results, f, indent=4)

        report_filename = generate_html_report(scan_results, timestamp)

        return redirect(url_for('view_scan_results', filename=filename))

    except Exception as e:
        flash(f'Error during scan: {str(e)}')
        return redirect(url_for('dashboard'))

@app.route('/view_scan/<filename>')
@login_required
def view_scan_results(filename):
    filepath = os.path.join(app.config['SCANS_DIR'], filename)
    
    if not os.path.exists(filepath):
        flash('Scan not found')
        return redirect(url_for('dashboard'))
    
    try:
        with open(filepath, 'r') as f:
            scan_data = json.load(f)
    except Exception as e:
        flash(f'Error loading scan data: {str(e)}')
        return redirect(url_for('dashboard'))
    
    timestamp = filename.replace('scan_', '').replace('.json', '')
    report_filename = f'report_{timestamp}.html'
    report_path = os.path.join(app.config['REPORTS_DIR'], report_filename)
    
    if not os.path.exists(report_path):
        flash('Report not found')
        return redirect(url_for('dashboard'))
    
    with open(report_path, 'r') as f:
        html_report = f.read()
    
    return render_template('scan_results.html', 
                          html_report=html_report,
                          filename=filename,
                          report_filename=report_filename)
@app.route('/download/json/<filename>')
@login_required
def download_json(filename):
    return send_from_directory(app.config['SCANS_DIR'], filename, as_attachment=True)

@app.route('/download/report/<filename>')
@login_required
def download_report(filename):
    return send_from_directory(app.config['REPORTS_DIR'], filename, as_attachment=True)

@app.route('/users')
@admin_required
def manage_users():
    print(User)
    return render_template('manage_users.html', users=users)

@app.route('/add_user', methods=['POST'])
@admin_required
def add_user():
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role')
    
    if username and password and role:
        users[username] = {
            'password': generate_password_hash(password),
            'role': role
        }
        flash(f'User {username} added successfully')
    else:
        flash('All fields are required')
    
    return redirect(url_for('manage_users'))

def get_available_scans():
    scans = []
    for filename in os.listdir(app.config['SCANS_DIR']):
        if filename.endswith('.json'):
            filepath = os.path.join(app.config['SCANS_DIR'], filename)
            with open(filepath, 'r') as f:
                try:
                    data = json.load(f)
                    timestamp = data.get('metadata', {}).get('timestamp', 'Unknown')
                    scan_name = data.get('metadata', {}).get('scan_name', 'Unnamed Scan')
                    target = data.get('metadata', {}).get('target', 'Unknown')
                    scans.append({
                        'filename': filename,
                        'timestamp': timestamp,
                        'name': scan_name,
                        'target': target
                    })
                except:
                    pass
    
    scans.sort(key=lambda x: x['timestamp'], reverse=True)
    return scans

def generate_html_report(scan_results, timestamp):
    """Generate a human-readable HTML report from scan results"""
    report_filename = f'report_{timestamp}.html'
    report_path = os.path.join(app.config['REPORTS_DIR'], report_filename)

    metadata = scan_results.get('metadata', {})
    scan_name = metadata.get('scan_name', 'Unnamed Scan')
    scan_time = metadata.get('timestamp', 'Unknown')
    target = metadata.get('target', 'Unknown')
    recon_ng_module = metadata.get('recon_ng_module', 'None')

    hosts_data = []
    total_open_ports = 0
    total_vulnerabilities = 0
    critical_vulnerabilities = 0

    for host_ip in scan_results.get('scan', {}):
        host_data = scan_results['scan'][host_ip]

        hostnames = [name['name'] for name in host_data.get('hostnames', [])]
        hostname_str = ', '.join(hostnames) if hostnames else 'Unknown'

        port_data = []
        host_open_ports = 0

        for protocol in ['tcp', 'udp']:
            if protocol in host_data:
                for port_num, port_info in host_data[protocol].items():
                    if port_info['state'] == 'open':
                        host_open_ports += 1
                        total_open_ports += 1

                        vulners_script = port_info.get('script', {}).get('vulners', '')
                        vulnerabilities = []

                        if vulners_script:
                            vulners_lines = vulners_script.split('\n')
                            for line in vulners_lines:
                                if 'CVE' in line:
                                    total_vulnerabilities += 1
                                    vulnerability = {
                                        'id': line.split()[0],
                                        'cvss': float(line.split()[1].strip('[]')) if len(line.split()) > 1 else 0
                                    }
                                    vulnerabilities.append(vulnerability)

                                    if vulnerability['cvss'] >= 9.0:
                                        critical_vulnerabilities += 1

                        port_data.append({
                            'port': port_num,
                            'protocol': protocol,
                            'service': port_info.get('name', 'unknown'),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'vulnerabilities': vulnerabilities
                        })

        hosts_data.append({
            'ip': host_ip,
            'hostname': hostname_str,
            'open_ports': host_open_ports,
            'ports': port_data
        })

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Scan Report: {scan_name}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background-color: #f0f0f0; padding: 15px; border-radius: 5px; }}
            .summary {{ background-color: #e9f7ef; padding: 15px; margin-top: 20px; border-radius: 5px; }}
            .host {{ background-color: #f8f9fa; padding: 15px; margin-top: 20px; border-radius: 5px; }}
            .ports {{ margin-top: 10px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .vuln-high {{ background-color: #ffcccc; }}
            .vuln-medium {{ background-color: #fff2cc; }}
            .vuln-low {{ background-color: #e6f2ff; }}
            .overview {{ display: flex; justify-content: space-between; }}
            .stat-box {{ background-color: #f8f9fa; padding: 15px; margin: 10px; border-radius: 5px; text-align: center; width: 30%; }}
            .critical {{ color: red; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Scan Report: {scan_name}</h1>
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Date:</strong> {scan_time}</p>
            <p><strong>User:</strong> {metadata.get('user', 'Unknown')}</p>
            <p><strong>Recon-ng Module:</strong> {recon_ng_module}</p>
        </div>

        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="overview">
                <div class="stat-box">
                    <h3>Hosts Scanned</h3>
                    <p><strong>{len(hosts_data)}</strong></p>
                </div>
                <div class="stat-box">
                    <h3>Open Ports</h3>
                    <p><strong>{total_open_ports}</strong></p>
                </div>
                <div class="stat-box">
                    <h3>Vulnerabilities</h3>
                    <p><strong>{total_vulnerabilities}</strong></p>
                    <p class="critical">Critical: {critical_vulnerabilities}</p>
                </div>
            </div>
        </div>
    """

    for host in hosts_data:
        html += f"""
        <div class="host">
            <h2>Host: {host['ip']}</h2>
            <p><strong>Hostname:</strong> {host['hostname']}</p>
            <p><strong>Open Ports:</strong> {host['open_ports']}</p>

            <div class="ports">
                <h3>Port Details</h3>
                <table>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Service</th>
                        <th>Product</th>
                        <th>Version</th>
                        <th>Vulnerabilities</th>
                    </tr>
        """

        for port in host['ports']:
            vuln_class = ""
            if any(v['cvss'] >= 9.0 for v in port['vulnerabilities']):
                vuln_class = "vuln-high"
            elif any(v['cvss'] >= 7.0 for v in port['vulnerabilities']):
                vuln_class = "vuln-medium"
            elif port['vulnerabilities']:
                vuln_class = "vuln-low"

            html += f"""
                <tr class="{vuln_class}">
                    <td>{port['port']}</td>
                    <td>{port['protocol']}</td>
                    <td>{port['service']}</td>
                    <td>{port['product']}</td>
                    <td>{port['version']}</td>
                    <td>
            """

            if port['vulnerabilities']:
                html += "<ul>"
                for vuln in sorted(port['vulnerabilities'], key=lambda x: x['cvss'], reverse=True):
                    severity = "Critical" if vuln['cvss'] >= 9.0 else "High" if vuln['cvss'] >= 7.0 else "Medium" if vuln['cvss'] >= 4.0 else "Low"
                    html += f"""<li>{vuln['id']} - CVSS: {vuln['cvss']} ({severity})</li>"""
                html += "</ul>"
            else:
                html += "None detected"

            html += """
                    </td>
                </tr>
            """

        html += """
                </table>
            </div>
        </div>
        """

    html += """
    </body>
    </html>
    """

    with open(report_path, 'w') as f:
        f.write(html)

    return report_filename

if __name__ == '__main__':
    app.run(debug=True)