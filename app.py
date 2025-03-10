from flask import Flask, render_template, request, jsonify
import nmap

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target')
    scan_type = request.form.get('scan_type', '-sV') 

    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments=scan_type)
        scan_results = nm.analyze_scan_results()
        return jsonify({
            'status': 'success',
            'results': scan_results
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

if __name__ == '__main__':
    app.run(debug=True)