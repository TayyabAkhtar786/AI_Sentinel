#!/usr/bin/env python3
"""
AI-Sentinel Dashboard Backend
Real-time web dashboard with WebSocket support
Fully JSON-safe for numpy / sklearn outputs
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner import NetworkScanner
from ai_analyzer import AIThreatAnalyzer
from attack_engine import AttackSimulator
from report_generator import ReportGenerator

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ai-sentinel-2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global state
scanner = NetworkScanner()
ai_analyzer = AIThreatAnalyzer()
reporter = ReportGenerator()

scan_results = []
ai_analysis = None
threat_summary = None
attack_report = None
target_ip = '127.0.0.1'


# ═══════════════════════════════════════════════════════
# JSON SAFE CONVERSION
# Fixes numpy.bool_, numpy.int64, numpy.float64, arrays
# ═══════════════════════════════════════════════════════
def make_json_safe(obj):
    """Recursively convert objects to JSON-safe Python types"""

    # Primitive safe types
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj

    # Dict
    if isinstance(obj, dict):
        return {str(k): make_json_safe(v) for k, v in obj.items()}

    # List / tuple / set
    if isinstance(obj, (list, tuple, set)):
        return [make_json_safe(item) for item in obj]

    # Bytes
    if isinstance(obj, bytes):
        try:
            return obj.decode('utf-8', errors='ignore')
        except Exception:
            return str(obj)

    # numpy arrays
    if hasattr(obj, 'tolist'):
        try:
            return make_json_safe(obj.tolist())
        except Exception:
            pass

    # numpy scalar types like numpy.bool_, numpy.int64, numpy.float64
    if hasattr(obj, 'item'):
        try:
            return make_json_safe(obj.item())
        except Exception:
            pass

    # datetime or other objects
    if hasattr(obj, 'isoformat'):
        try:
            return obj.isoformat()
        except Exception:
            pass

    # fallback
    return str(obj)


# ═══════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════

@app.route('/')
def dashboard():
    return render_template('index.html')


@app.route('/api/status')
def api_status():
    return jsonify(make_json_safe({
        'status': 'online',
        'ai_loaded': ai_analyzer.is_trained,
        'ai_accuracy': f"{ai_analyzer.accuracy:.2%}" if ai_analyzer.accuracy else 'N/A',
        'has_scan': len(scan_results) > 0,
        'has_analysis': ai_analysis is not None,
        'has_attack': attack_report is not None,
        'timestamp': datetime.now().isoformat()
    }))


@app.route('/api/scan', methods=['POST'])
def api_scan():
    global target_ip

    data = request.json or {}
    target_ip = data.get('target', '127.0.0.1')
    scan_type = data.get('type', 'quick')

    thread = threading.Thread(target=run_scan, args=(target_ip, scan_type), daemon=True)
    thread.start()

    return jsonify(make_json_safe({
        'status': 'started',
        'target': target_ip,
        'type': scan_type
    }))


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    global ai_analysis, threat_summary

    if not scan_results:
        return jsonify({'error': 'Run a scan first'}), 400

    ai_analysis, threat_summary = ai_analyzer.analyze_full_scan(scan_results)

    payload = make_json_safe({
        'summary': threat_summary,
        'analysis': ai_analysis
    })

    socketio.emit('analysis_complete', payload)

    return jsonify(make_json_safe({
        'status': 'complete',
        'summary': payload['summary']
    }))


@app.route('/api/attack', methods=['POST'])
def api_attack():
    global attack_report

    if not ai_analysis:
        return jsonify({'error': 'Run AI analysis first'}), 400

    def run_attack():
        global attack_report

        simulator = AttackSimulator(
            target=target_ip,
            log_callback=lambda log: socketio.emit('attack_log', make_json_safe(log))
        )

        attack_report = simulator.run_full_assessment(ai_analysis, threat_summary)

        safe_report = make_json_safe({
            'report': attack_report
        })

        socketio.emit('attack_complete', safe_report)

    thread = threading.Thread(target=run_attack, daemon=True)
    thread.start()

    return jsonify(make_json_safe({
        'status': 'started'
    }))


@app.route('/api/report', methods=['POST'])
def api_report():
    if not ai_analysis:
        return jsonify({'error': 'Run analysis first'}), 400

    path = reporter.generate(
        scan_results=scan_results,
        ai_analysis=ai_analysis,
        threat_summary=threat_summary,
        attack_report=attack_report,
        target_ip=target_ip
    )

    return jsonify(make_json_safe({
        'status': 'complete',
        'path': path
    }))


@app.route('/api/results')
def api_results():
    return jsonify(make_json_safe({
        'scan': scan_results,
        'ai_analysis': ai_analysis,
        'threat_summary': threat_summary,
        'attack_report': attack_report
    }))


# ═══════════════════════════════════════════════════════
# BACKGROUND TASKS
# ═══════════════════════════════════════════════════════

def run_scan(ip, scan_type):
    global scan_results

    socketio.emit('scan_update', make_json_safe({
        'status': 'started',
        'message': f'Starting {scan_type} scan on {ip}...'
    }))

    try:
        if scan_type == 'quick':
            scan_results = scanner.quick_scan(ip)
        elif scan_type == 'deep':
            scan_results = scanner.deep_scan(ip)
        elif scan_type == 'adaptive':
            scan_results = scanner.adaptive_scan(ip)
        else:
            scan_results = scanner.quick_scan(ip)

        summary = scanner.get_summary(scan_results)

        socketio.emit('scan_update', make_json_safe({
            'status': 'complete',
            'message': f'Scan complete! {summary.get("total_ports", 0)} ports found.',
            'results': scan_results,
            'summary': summary
        }))

    except Exception as e:
        socketio.emit('scan_update', make_json_safe({
            'status': 'error',
            'message': f'Scan failed: {str(e)}'
        }))


# ═══════════════════════════════════════════════════════
# SOCKET EVENTS
# ═══════════════════════════════════════════════════════

@socketio.on('connect')
def handle_connect():
    emit('connected', make_json_safe({
        'status': 'AI-Sentinel Connected!',
        'timestamp': datetime.now().isoformat()
    }))


# ═══════════════════════════════════════════════════════
# INITIALIZATION
# ═══════════════════════════════════════════════════════

def initialize():
    print("\n🚀 AI-Sentinel Starting...")
    print("   Initializing AI model...")

    if not ai_analyzer.load_model():
        print("   No trained model found. Training new model...")
        ai_analyzer.train()

    print("   ✅ System ready!")
    print()


# ═══════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════

if __name__ == '__main__':
    initialize()
    print("🖥️  Dashboard: http://localhost:8080")
    print("⚠️  Run only in authorized lab environments")
    print()
    socketio.run(
        app,
        host='0.0.0.0',
        port=8080,
        debug=False,
        allow_unsafe_werkzeug=True
    )
