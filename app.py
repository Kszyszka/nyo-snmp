from flask import Flask, render_template, request, jsonify, redirect, url_for, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import ipaddress
from snmp_operations import scan_ip, check_device_status, get_device_name, find_active_ips, get_system_metrics
import threading
import time
import json
import os
import logging
import queue
from flask_sse import sse

# Configure logging
logging.basicConfig(level=logging.INFO,
                   format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///devices.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configuration file path
CONFIG_FILE = 'config.json'

# Default configuration
DEFAULT_CONFIG = {
    'check_interval': 300  # 5 minutes in seconds
}

# Global variables
current_check_interval = None
last_check_time = datetime.now(timezone.utc)
checking_active = True
check_cycle_complete = False
interval_changed = False

# Global progress queue for scan updates
scan_progress_queue = queue.Queue()

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return DEFAULT_CONFIG

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f)

# Initialize current_check_interval from config
config = load_config()
current_check_interval = config['check_interval']
logger.info(f"Initialized check interval to {current_check_interval} seconds from config")

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(15), unique=True, nullable=False)
    name = db.Column(db.String(100))
    status = db.Column(db.String(20))
    last_checked = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    snmp_community = db.Column(db.String(50), default='public')
    uptime = db.Column(db.String(50))
    cpu_usage = db.Column(db.Float)
    memory_used = db.Column(db.Integer)  # in MB
    memory_total = db.Column(db.Integer)  # in MB

def check_all_devices():
    """Check status of all devices in the database"""
    with app.app_context():
        devices = Device.query.all()
        for device in devices:
            try:
                # Check if device is responding to SNMP
                is_active = check_device_status(device.ip_address, device.snmp_community)
                device.status = 'active' if is_active else 'inactive'
                
                # If device is active, try to get its name and metrics
                if is_active:
                    # Get device name if unknown
                    if device.name == 'Unknown':
                        try:
                            device_name = get_device_name(device.ip_address, device.snmp_community)
                            if device_name:
                                device.name = device_name
                        except Exception as e:
                            logging.error(f"Error getting device name for {device.ip_address}: {str(e)}")
                    
                    # Get system metrics
                    try:
                        metrics = get_system_metrics(device.ip_address, device.snmp_community)
                        if metrics:
                            device.uptime = metrics.get('uptime')
                            device.cpu_usage = metrics.get('cpu_usage')
                            device.memory_used = metrics.get('memory_used')
                            device.memory_total = metrics.get('memory_total')
                    except Exception as e:
                        logging.error(f"Error getting metrics for {device.ip_address}: {str(e)}")
                
                device.last_checked = datetime.now(timezone.utc)
                db.session.commit()
            except Exception as e:
                logging.error(f"Error checking device {device.ip_address}: {str(e)}")
                device.status = 'inactive'
                device.last_checked = datetime.now(timezone.utc)
                db.session.commit()

# Start the background checking thread
checking_thread = threading.Thread(target=check_all_devices, daemon=True)
checking_thread.start()

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    devices = Device.query.all()
    config = load_config()
    return render_template('index.html', 
                         devices=devices, 
                         check_interval=config['check_interval'],
                         last_check_time=last_check_time)

@app.route('/get_last_check_time')
def get_last_check_time():
    global last_check_time, check_cycle_complete, interval_changed
    response = {
        'last_check_time': last_check_time.strftime('%Y-%m-%d %H:%M:%S'),
        'check_cycle_complete': check_cycle_complete,
        'interval_changed': interval_changed
    }
    # Reset the flags after sending
    check_cycle_complete = False
    interval_changed = False
    return jsonify(response)

@app.route('/update_check_interval', methods=['POST'])
def update_check_interval():
    global current_check_interval, interval_changed
    try:
        interval = int(request.form.get('interval', 300))
        if interval < 30:  # Minimum 30 seconds
            return jsonify({'error': 'Interval must be at least 30 seconds'}), 400
            
        config = load_config()
        config['check_interval'] = interval
        save_config(config)
        
        # Update the global interval variable immediately
        current_check_interval = interval
        interval_changed = True
        logger.info(f"Check interval updated to {interval} seconds")
        
        return jsonify({'message': 'Check interval updated successfully'})
    except ValueError:
        return jsonify({'error': 'Invalid interval value'}), 400

@app.route('/add_device', methods=['POST'])
def add_device():
    ip = request.form.get('ip_address')
    community = request.form.get('snmp_community', 'public')
    
    try:
        # Validate IP address
        ipaddress.ip_address(ip)
        
        # Check if device exists
        existing_device = Device.query.filter_by(ip_address=ip).first()
        if existing_device:
            return jsonify({'error': 'Device already exists'}), 400
        
        # Try to scan the device
        if scan_ip(ip, community):
            # Try to get device name
            name = None
            try:
                name = get_device_name(ip, community)
            except Exception as e:
                logger.error(f"Error getting device name: {str(e)}")
            
            device = Device(
                ip_address=ip,
                snmp_community=community,
                status='active',
                name=name or 'Unknown'
            )
            db.session.add(device)
            db.session.commit()
            return redirect(url_for('index'))
        else:
            return jsonify({'error': 'Could not connect to device via SNMP'}), 400
            
    except ValueError:
        return jsonify({'error': 'Invalid IP address'}), 400

def scan_range_worker(ip_range, community):
    # Create application context for the background thread
    with app.app_context():
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            total_ips = sum(1 for _ in network.hosts())
            
            # Find active IPs
            active_ips = find_active_ips(ip_range)
            scan_progress_queue.put({
                'type': 'active_ips',
                'count': len(active_ips),
                'total': total_ips
            })
            
            found_devices = []
            scanned_count = 0
            
            for ip in active_ips:
                try:
                    # Check if device already exists
                    existing_device = Device.query.filter_by(ip_address=ip).first()
                    if existing_device:
                        continue
                        
                    # Try to scan the device
                    if scan_ip(ip, community):
                        # Try to get device name
                        name = None
                        try:
                            name = get_device_name(ip, community)
                        except Exception as e:
                            logger.error(f"Error getting device name for {ip}: {str(e)}")
                        
                        device = Device(
                            ip_address=ip,
                            snmp_community=community,
                            status='active',
                            name=name or 'Unknown'
                        )
                        db.session.add(device)
                        found_devices.append(ip)
                    
                    scanned_count += 1
                    scan_progress_queue.put({
                        'type': 'progress',
                        'scanned': scanned_count,
                        'total': len(active_ips),
                        'found': len(found_devices)
                    })
                    
                except Exception as e:
                    logger.error(f"Error scanning {ip}: {str(e)}")
                    continue
            
            try:
                db.session.commit()
                scan_progress_queue.put({
                    'type': 'complete',
                    'message': f'Found {len(found_devices)} new devices',
                    'devices': found_devices,
                    'total_ips': total_ips,
                    'active_ips': len(active_ips),
                    'scanned': scanned_count
                })
            except Exception as e:
                logger.error(f"Database error: {str(e)}")
                db.session.rollback()
                scan_progress_queue.put({
                    'type': 'error',
                    'error': f'Database error: {str(e)}'
                })
                
        except Exception as e:
            logger.error(f"Unexpected error in scan_range_worker: {str(e)}")
            scan_progress_queue.put({
                'type': 'error',
                'error': f'Unexpected error: {str(e)}'
            })

@app.route('/scan_range', methods=['POST'])
def scan_range():
    try:
        ip_range = request.form.get('ip_range')
        community = request.form.get('snmp_community', 'public')
        
        if not ip_range:
            return jsonify({'error': 'IP range is required'}), 400
            
        # Start scan in background thread
        thread = threading.Thread(target=scan_range_worker, args=(ip_range, community))
        thread.daemon = True
        thread.start()
        
        return jsonify({'message': 'Scan started'})
            
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return jsonify({'error': f'Error starting scan: {str(e)}'}), 500

@app.route('/scan_progress')
def scan_progress():
    def generate():
        while True:
            try:
                # Get progress update from queue
                progress = scan_progress_queue.get(timeout=30)
                yield f"data: {json.dumps(progress)}\n\n"
                
                # If scan is complete or error occurred, stop sending updates
                if progress['type'] in ['complete', 'error']:
                    break
                    
            except queue.Empty:
                # No updates for 30 seconds, send heartbeat
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
                
    return Response(generate(), mimetype='text/event-stream')

@app.route('/check_status/<int:device_id>')
def check_status(device_id):
    """Check status of a specific device"""
    device = Device.query.get_or_404(device_id)
    try:
        is_active = check_device_status(device.ip_address, device.snmp_community)
        device.status = 'active' if is_active else 'inactive'
        
        # If device is active, try to get its name and metrics
        if is_active:
            # Get device name if unknown
            if device.name == 'Unknown':
                try:
                    device_name = get_device_name(device.ip_address, device.snmp_community)
                    if device_name:
                        device.name = device_name
                except Exception as e:
                    logging.error(f"Error getting device name for {device.ip_address}: {str(e)}")
            
            # Get system metrics
            try:
                metrics = get_system_metrics(device.ip_address, device.snmp_community)
                if metrics:
                    device.uptime = metrics.get('uptime')
                    device.cpu_usage = metrics.get('cpu_usage')
                    device.memory_used = metrics.get('memory_used')
                    device.memory_total = metrics.get('memory_total')
            except Exception as e:
                logging.error(f"Error getting metrics for {device.ip_address}: {str(e)}")
        
        device.last_checked = datetime.now(timezone.utc)
        db.session.commit()
        return jsonify({'status': 'success', 'message': f'Device {device.ip_address} is {device.status}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/delete_device/<int:device_id>', methods=['POST'])
def delete_device(device_id):
    device = Device.query.get_or_404(device_id)
    db.session.delete(device)
    db.session.commit()
    return jsonify({'message': 'Device deleted successfully'})

@app.route('/delete_devices', methods=['POST'])
def delete_devices():
    device_ids = request.json.get('device_ids', [])
    if not device_ids:
        return jsonify({'error': 'No devices selected'}), 400
    
    Device.query.filter(Device.id.in_(device_ids)).delete(synchronize_session=False)
    db.session.commit()
    return jsonify({'message': f'Successfully deleted {len(device_ids)} devices'})

@app.route('/check_all_devices_now')
def check_all_devices_now():
    devices = Device.query.all()
    for device in devices:
        try:
            status = check_device_status(device.ip_address, device.snmp_community)
            device.status = 'active' if status else 'inactive'
            device.last_checked = datetime.now(timezone.utc)
            
            # Try to get device name if status is active
            if status and (not device.name or device.name == 'Unknown'):
                try:
                    name = get_device_name(device.ip_address, device.snmp_community)
                    if name:
                        device.name = name
                except Exception as e:
                    logger.error(f"Error getting device name: {str(e)}")
        except Exception as e:
            logger.error(f"Error checking device {device.ip_address}: {str(e)}")
            device.status = 'inactive'
            device.last_checked = datetime.now(timezone.utc)
    
    db.session.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True) 