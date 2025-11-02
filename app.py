"""
Demo Application for Security Scanner API
Simple Flask app for browser-based demonstration
"""
from flask import Flask, render_template, request, jsonify, redirect, url_for
import requests
import json
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'demo-secret-key-change-in-production'

# API Base URL - change this to your FastAPI server URL
API_BASE_URL = "http://localhost:8000"

@app.route('/')
def index():
    """Redirect to scanner page."""
    return redirect(url_for('scanner'))

@app.route('/scanner')
def scanner():
    """Scanner interface page."""
    logger.info("Scanner page accessed")
    return render_template('index.html')

@app.route('/admin-panel')
def admin_panel():
    """Admin panel page."""
    logger.info("Admin panel page accessed")
    return render_template('admin.html')

@app.route('/api/scan', methods=['POST'])
def scan():
    """Proxy scan request to FastAPI backend."""
    try:
        data = request.get_json()
        logger.info(f"Scan request: type={data.get('scan_type')}, data_length={len(data.get('input_data', ''))}")
        
        # Forward request to FastAPI
        response = requests.post(
            f"{API_BASE_URL}/api/scan",
            json=data,
            timeout=30
        )
        
        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            logger.error(f"API error: {response.status_code} - {response.text}")
            return jsonify({
                'success': False,
                'detail': response.json().get('detail', 'API request failed')
            }), response.status_code
            
    except requests.exceptions.ConnectionError:
        logger.error("Cannot connect to FastAPI server. Is it running?")
        return jsonify({
            'success': False,
            'detail': 'Cannot connect to API server. Please ensure FastAPI server is running on ' + API_BASE_URL
        }), 503
    except Exception as e:
        logger.error(f"Scan error: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'detail': f'Error: {str(e)}'
        }), 500

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    """Proxy admin login request to FastAPI backend."""
    try:
        data = request.get_json()
        logger.info(f"Login attempt for user: {data.get('username')}")
        
        # Forward request to FastAPI
        response = requests.post(
            f"{API_BASE_URL}/api/admin/login",
            json=data,
            timeout=30
        )
        
        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            logger.error(f"Login error: {response.status_code}")
            return jsonify({
                'detail': response.json().get('detail', 'Login failed')
            }), response.status_code
            
    except requests.exceptions.ConnectionError:
        logger.error("Cannot connect to FastAPI server")
        return jsonify({
            'detail': 'Cannot connect to API server. Please ensure FastAPI server is running.'
        }), 503
    except Exception as e:
        logger.error(f"Login error: {str(e)}", exc_info=True)
        return jsonify({
            'detail': f'Error: {str(e)}'
        }), 500

@app.route('/api/admin/<path:endpoint>', methods=['GET', 'POST', 'PUT'])
def admin_proxy(endpoint):
    """Proxy admin API requests to FastAPI backend."""
    try:
        # Get authorization token from headers
        auth_header = request.headers.get('Authorization')
        headers = {}
        if auth_header:
            headers['Authorization'] = auth_header
        
        # Get query parameters
        params = request.args.to_dict()
        
        # Forward request to FastAPI
        if request.method == 'GET':
            response = requests.get(
                f"{API_BASE_URL}/api/admin/{endpoint}",
                headers=headers,
                params=params,
                timeout=30
            )
        elif request.method == 'POST':
            response = requests.post(
                f"{API_BASE_URL}/api/admin/{endpoint}",
                headers=headers,
                json=request.get_json(),
                timeout=30
            )
        elif request.method == 'PUT':
            response = requests.put(
                f"{API_BASE_URL}/api/admin/{endpoint}",
                headers=headers,
                json=request.get_json(),
                timeout=30
            )
        
        if response.status_code == 200:
            return jsonify(response.json()), 200
        else:
            logger.error(f"Admin API error: {response.status_code}")
            return jsonify({
                'detail': response.json().get('detail', 'API request failed')
            }), response.status_code
            
    except requests.exceptions.ConnectionError:
        logger.error("Cannot connect to FastAPI server")
        return jsonify({
            'detail': 'Cannot connect to API server. Please ensure FastAPI server is running.'
        }), 503
    except Exception as e:
        logger.error(f"Admin API error: {str(e)}", exc_info=True)
        return jsonify({
            'detail': f'Error: {str(e)}'
        }), 500

@app.route('/health')
def health():
    """Health check endpoint."""
    try:
        response = requests.get(f"{API_BASE_URL}/api/health", timeout=5)
        return jsonify({
            'demo_app': 'healthy',
            'api_server': 'connected' if response.status_code == 200 else 'disconnected',
            'api_status': response.json() if response.status_code == 200 else None
        }), 200
    except:
        return jsonify({
            'demo_app': 'healthy',
            'api_server': 'disconnected'
        }), 200

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("🌐 Security Scanner API - Demo Application")
    print("=" * 60)
    print(f"📍 Demo URL: http://localhost:5000")
    print(f"🔍 Scanner: http://localhost:5000/scanner")
    print(f"🔐 Admin Panel: http://localhost:5000/admin-panel")
    print("=" * 60)
    print("\n⚠️  Note: This is a demo app. It requires FastAPI server")
    print(f"   running on {API_BASE_URL}")
    print("\n" + "=" * 60 + "\n")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )

