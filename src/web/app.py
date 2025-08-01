"""
Web Application Module
Flask-based web interface for Metasploit-AI Framework
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import json
import asyncio
from datetime import datetime, timedelta
from functools import wraps
import uuid
import hashlib
import os
import re
from collections import defaultdict

from ..utils.logger import get_logger

# Rate limiting storage
request_counts = defaultdict(lambda: defaultdict(int))
request_times = defaultdict(list)

def validate_input(data, field_name, field_type='string', max_length=None, required=True, pattern=None):
    """Validate input data"""
    if required and (not data or field_name not in data):
        raise ValueError(f"{field_name} is required")
    
    if field_name not in data:
        return None
    
    value = data[field_name]
    
    if field_type == 'string' and not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    
    if field_type == 'int' and not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    
    if field_type == 'list' and not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list")
    
    if max_length and len(str(value)) > max_length:
        raise ValueError(f"{field_name} exceeds maximum length of {max_length}")
    
    if pattern and isinstance(value, str) and not re.match(pattern, value):
        raise ValueError(f"{field_name} has invalid format")
    
    return value

def rate_limit_check(ip_address, endpoint, limit=100, window=60):
    """Check rate limiting"""
    now = datetime.now()
    
    # Clean old entries
    request_times[ip_address] = [t for t in request_times[ip_address] 
                                if (now - t).seconds < window]
    
    # Check current count
    if len(request_times[ip_address]) >= limit:
        return False
    
    # Add current request
    request_times[ip_address].append(now)
    return True

def create_web_app(framework):
    """Create and configure Flask web application"""
    
    logger = get_logger('web_app')
    
    import os
    
    # Get the absolute path to the web directory
    web_dir = os.path.dirname(os.path.abspath(__file__))
    
    app = Flask(__name__, 
                template_folder=os.path.join(web_dir, 'templates'),
                static_folder=os.path.join(web_dir, 'static'))
    
    # Configuration
    app.config['SECRET_KEY'] = framework.config.web.secret_key if hasattr(framework.config, 'web') else os.getenv('SECRET_KEY', 'dev-secret-key')
    if app.config['SECRET_KEY'] == 'change-this-secret-key':
        if not framework.config.framework.get('debug', False):
            logger.error("🚨 SECURITY WARNING: Using default secret key in production!")
            raise ValueError("Production deployment requires secure SECRET_KEY")
        else:
            logger.warning("⚠️ Using default secret key - OK for development only")
    
    app.config['SESSION_PERMANENT'] = True
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=getattr(framework.config.web, 'session_timeout', 3600) if hasattr(framework.config, 'web') else 3600)
    
    # Enable CORS
    CORS(app)
    
    # Initialize SocketIO for real-time updates
    socketio = SocketIO(app, cors_allowed_origins="*")
    
    logger = get_logger(__name__)
    
    def run_async_safely(async_func):
        """Safely run async function in Flask route"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(async_func())
            return result
        except Exception as e:
            logger.error(f"Async execution failed: {e}")
            raise
        finally:
            try:
                loop.close()
            except:
                pass
    
    logger = get_logger(__name__)
    
    # Rate limiting middleware
    @app.before_request
    def before_request():
        """Rate limiting and security checks"""
        if request.endpoint and request.endpoint.startswith('api_'):
            ip_address = request.remote_addr
            rate_limit = framework.config.security.rate_limit if hasattr(framework.config, 'security') else 100
            
            if not rate_limit_check(ip_address, request.endpoint, rate_limit):
                logger.warning(f"Rate limit exceeded for {ip_address} on {request.endpoint}")
                return jsonify({'error': 'Rate limit exceeded'}), 429
    
    # Authentication decorator
    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('authenticated'):
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    
    # API key decorator
    def api_key_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not framework.config.security.api_key_required:
                return f(*args, **kwargs)
            
            api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
            if not api_key or not validate_api_key(api_key):
                return jsonify({'error': 'Invalid or missing API key'}), 401
            
            return f(*args, **kwargs)
        return decorated_function
    
    def validate_api_key(api_key: str) -> bool:
        """Validate API key"""
        # TODO: Implement proper API key validation with database
        # For production, use environment variables or secure key management
        valid_keys = os.getenv('VALID_API_KEYS', '').split(',') if os.getenv('VALID_API_KEYS') else []
        
        # Fallback for development only
        if not valid_keys and framework.config.framework.get('debug', False):
            logger.warning("⚠️ Using development API keys - NOT FOR PRODUCTION!")
            valid_keys = ['dev-api-key']
            
        return api_key in valid_keys
    
    @app.route('/')
    def index():
        """Main dashboard"""
        if not session.get('authenticated'):
            return redirect(url_for('login'))
        return render_template('dashboard.html')
    
    @app.route('/favicon.ico')
    def favicon():
        """Serve favicon"""
        return app.send_static_file('favicon.ico')
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """Login page"""
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            
            # Input validation
            if not username or not password:
                return render_template('login.html', error='Username and password required')
            
            if len(username) > 50 or len(password) > 100:
                return render_template('login.html', error='Invalid input length')
            
            # Authentication - Use environment variables for production
            admin_username = os.getenv('ADMIN_USERNAME', 'admin')
            admin_password = os.getenv('ADMIN_PASSWORD', 'admin')
            
            # Add password hashing for production
            if username == admin_username and password == admin_password:
                if not framework.config.framework.get('debug', False):
                    logger.warning(f"⚠️ Login attempt with default credentials from {request.remote_addr}")
                
                session['authenticated'] = True
                session['username'] = username
                session['login_time'] = datetime.now().isoformat()
                session['ip_address'] = request.remote_addr
                return redirect(url_for('index'))
            else:
                logger.warning(f"❌ Failed login attempt for '{username}' from {request.remote_addr}")
                return render_template('login.html', error='Invalid credentials')
        
        return render_template('login.html')
    
    @app.route('/logout')
    def logout():
        """Logout"""
        session.clear()
        return redirect(url_for('login'))
    
    @app.route('/scanner')
    @login_required
    def scanner():
        """Scanner interface"""
        return render_template('scanner.html')
    
    @app.route('/exploits')
    @login_required
    def exploits():
        """Exploits interface"""
        return render_template('exploits.html')
    
    @app.route('/payloads')
    @login_required
    def payloads():
        """Payloads interface"""
        return render_template('payloads.html')
    
    @app.route('/reports')
    @login_required
    def reports():
        """Reports interface"""
        return render_template('reports.html')
    
    @app.route('/settings')
    @login_required
    def settings():
        """Settings interface"""
        return render_template('settings.html')
    
    # API Routes
    @app.route('/api/status')
    @api_key_required
    def api_status():
        """Get framework status"""
        try:
            status = framework.get_status()
            return jsonify({
                'success': True,
                'data': status
            })
        except Exception as e:
            logger.error(f"Status API error: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/scan', methods=['POST'])
    @api_key_required
    def api_scan():
        """Start network scan"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({
                    'success': False,
                    'error': 'JSON data required'
                }), 400
            
            # Input validation
            try:
                target = validate_input(data, 'target', 'string', max_length=255, required=True, 
                                       pattern=r'^[a-zA-Z0-9.\-/]+$')
                scan_type = validate_input(data, 'scan_type', 'string', max_length=50, required=False)
                if not scan_type:
                    scan_type = 'comprehensive'
                    
                # Validate scan_type
                allowed_scan_types = ['quick', 'comprehensive', 'stealth', 'aggressive']
                if scan_type not in allowed_scan_types:
                    return jsonify({
                        'success': False,
                        'error': f'Invalid scan_type. Allowed: {allowed_scan_types}'
                    }), 400
                    
            except ValueError as e:
                return jsonify({
                    'success': False,
                    'error': str(e)
                }), 400
            
            # Start scan asynchronously
            scan_id = str(uuid.uuid4())
            
            async def run_scan():
                try:
                    result = await framework.scan_target(target, scan_type)
                    socketio.emit('scan_complete', {
                        'scan_id': scan_id,
                        'result': result.__dict__ if hasattr(result, '__dict__') else result
                    })
                except Exception as e:
                    socketio.emit('scan_error', {
                        'scan_id': scan_id,
                        'error': str(e)
                    })
            
            # Run in background
            asyncio.create_task(run_scan())
            
            return jsonify({
                'success': True,
                'scan_id': scan_id,
                'message': 'Scan started'
            })
            
        except Exception as e:
            logger.error(f"Scan API error: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/exploits/recommend', methods=['POST'])
    @api_key_required
    def api_recommend_exploits():
        """Get exploit recommendations"""
        try:
            data = request.get_json()
            target = data.get('target')
            vulnerabilities = data.get('vulnerabilities', [])
            
            if not target or not vulnerabilities:
                return jsonify({
                    'success': False,
                    'error': 'Target and vulnerabilities are required'
                }), 400
            
            async def get_recommendations():
                return await framework.recommend_exploits(target, vulnerabilities)
            
            # Run async function safely
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                recommendations = loop.run_until_complete(get_recommendations())
            except Exception as e:
                logger.error(f"Failed to get recommendations: {e}")
                return jsonify({
                    'success': False,
                    'error': 'Failed to generate recommendations'
                }), 500
            finally:
                loop.close()
            
            return jsonify({
                'success': True,
                'data': recommendations
            })
            
        except Exception as e:
            logger.error(f"Exploit recommendation API error: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/exploit/execute', methods=['POST'])
    @api_key_required
    def api_execute_exploit():
        """Execute exploit"""
        try:
            data = request.get_json()
            target = data.get('target')
            exploit_name = data.get('exploit_name')
            options = data.get('options', {})
            
            if not target or not exploit_name:
                return jsonify({
                    'success': False,
                    'error': 'Target and exploit_name are required'
                }), 400
            
            # Execute exploit asynchronously
            exploit_id = str(uuid.uuid4())
            
            async def run_exploit():
                try:
                    result = await framework.execute_exploit(target, exploit_name, options)
                    socketio.emit('exploit_complete', {
                        'exploit_id': exploit_id,
                        'result': result.__dict__ if hasattr(result, '__dict__') else result
                    })
                except Exception as e:
                    socketio.emit('exploit_error', {
                        'exploit_id': exploit_id,
                        'error': str(e)
                    })
            
            # Run in background
            asyncio.create_task(run_exploit())
            
            return jsonify({
                'success': True,
                'exploit_id': exploit_id,
                'message': 'Exploit execution started'
            })
            
        except Exception as e:
            logger.error(f"Exploit execution API error: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/payload/generate', methods=['POST'])
    @api_key_required
    def api_generate_payload():
        """Generate payload"""
        try:
            data = request.get_json()
            target = data.get('target')
            exploit_name = data.get('exploit_name')
            options = data.get('options', {})
            
            if not target or not exploit_name:
                return jsonify({
                    'success': False,
                    'error': 'Target and exploit_name are required'
                }), 400
            
            async def generate():
                return await framework.payload_generator.generate(target, exploit_name, options)
            
            # Run async function safely
            try:
                payload = run_async_safely(generate)
            except Exception as e:
                logger.error(f"Failed to generate payload: {e}")
                return jsonify({
                    'success': False,
                    'error': 'Failed to generate payload'
                }), 500
            
            return jsonify({
                'success': True,
                'data': {'payload': payload}
            })
            
        except Exception as e:
            logger.error(f"Payload generation API error: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/autotest', methods=['POST'])
    @api_key_required
    def api_automated_test():
        """Run automated penetration test"""
        try:
            data = request.get_json()
            targets = data.get('targets', [])
            
            if not targets:
                return jsonify({
                    'success': False,
                    'error': 'Targets are required'
                }), 400
            
            # Start automated test
            test_id = str(uuid.uuid4())
            
            async def run_test():
                try:
                    result = await framework.automated_penetration_test(targets)
                    socketio.emit('autotest_complete', {
                        'test_id': test_id,
                        'result': result
                    })
                except Exception as e:
                    socketio.emit('autotest_error', {
                        'test_id': test_id,
                        'error': str(e)
                    })
            
            # Run in background
            asyncio.create_task(run_test())
            
            return jsonify({
                'success': True,
                'test_id': test_id,
                'message': 'Automated test started'
            })
            
        except Exception as e:
            logger.error(f"Automated test API error: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/msf/exploits')
    @api_key_required
    def api_msf_exploits():
        """Get Metasploit exploits"""
        try:
            async def get_exploits():
                return await framework.msf_client.get_exploits()
            
            try:
                exploits = run_async_safely(get_exploits)
            except Exception as e:
                logger.error(f"Failed to get exploits: {e}")
                return jsonify({
                    'success': False,
                    'error': 'Failed to retrieve exploits'
                }), 500
            
            return jsonify({
                'success': True,
                'data': exploits
            })
            
        except Exception as e:
            logger.error(f"MSF exploits API error: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/msf/payloads')
    @api_key_required
    def api_msf_payloads():
        """Get Metasploit payloads"""
        try:
            async def get_payloads():
                return await framework.msf_client.get_payloads()
            
            try:
                payloads = run_async_safely(get_payloads)
            except Exception as e:
                logger.error(f"Failed to get payloads: {e}")
                return jsonify({
                    'success': False,
                    'error': 'Failed to retrieve payloads'
                }), 500
            
            return jsonify({
                'success': True,
                'data': payloads
            })
            
        except Exception as e:
            logger.error(f"MSF payloads API error: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    # SocketIO Events
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        logger.info("Client connected to WebSocket")
        emit('status', {'message': 'Connected to Metasploit-AI'})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection"""
        logger.info("Client disconnected from WebSocket")
    
    @socketio.on('get_status')
    def handle_get_status():
        """Handle status request"""
        try:
            status = framework.get_status()
            emit('status_update', status)
        except Exception as e:
            emit('error', {'message': str(e)})
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return render_template('error.html', 
                             error_code=404, 
                             error_message="Page not found"), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return render_template('error.html', 
                             error_code=500, 
                             error_message="Internal server error"), 500
    
    # Template filters
    @app.template_filter('datetime')
    def datetime_filter(timestamp):
        """Format datetime for templates"""
        if isinstance(timestamp, str):
            try:
                dt = datetime.fromisoformat(timestamp)
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                return timestamp
        return str(timestamp)
    
    @app.template_filter('severity_class')
    def severity_class_filter(severity):
        """Get CSS class for severity level"""
        severity_classes = {
            'Critical': 'danger',
            'High': 'warning',
            'Medium': 'info',
            'Low': 'secondary'
        }
        return severity_classes.get(severity, 'secondary')
    
    # Context processors
    @app.context_processor
    def inject_framework_info():
        """Inject framework information into templates"""
        return {
            'framework_name': getattr(framework.config, 'name', 'Metasploit-AI'),
            'framework_version': getattr(framework.config, 'version', '1.0.0'),
            'current_user': session.get('username', 'Anonymous')
        }
    
    # Initialize SocketIO
    socketio = SocketIO(app, cors_allowed_origins="*")
    
    logger.info("Web application initialized successfully")
    return app, socketio
