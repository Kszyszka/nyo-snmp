from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import ipaddress
from snmp_operations import scan_ip, check_device_status
import threading
import time
import json
import os

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
current_check_interval = DEFAULT_CONFIG['check_interval']
last_check_time = datetime.utcnow()

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return DEFAULT_CONFIG

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(15), unique=True, nullable=False)
    name = db.Column(db.String(100))
    status = db.Column(db.String(20))
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)
    snmp_community = db.Column(db.String(50), default='public')

def check_all_devices():
    global current_check_interval, last_check_time
    with app.app_context():
        while True:
            try:
                devices = Device.query.all()
                for device in devices:
                    try:
                        status = check_device_status(device.ip_address, device.snmp_community)
                        device.status = 'active' if status else 'inactive'
                        device.last_checked = datetime.utcnow()
                    except Exception:
                        device.status = 'inactive'
                        device.last_checked = datetime.utcnow()
                db.session.commit()
                last_check_time = datetime.utcnow()
            except Exception as e:
                print(f"Error during device check: {str(e)}")
            
            # Sleep for the current interval
            time.sleep(current_check_interval)

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
    return jsonify({'last_check_time': last_check_time.strftime('%Y-%m-%d %H:%M:%S')})

@app.route('/update_check_interval', methods=['POST'])
def update_check_interval():
    global current_check_interval
    try:
        interval = int(request.form.get('interval', 300))
        if interval < 30:  # Minimum 30 seconds
            return jsonify({'error': 'Interval must be at least 30 seconds'}), 400
            
        config = load_config()
        config['check_interval'] = interval
        save_config(config)
        
        # Update the global interval variable immediately
        current_check_interval = interval
        
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
            device = Device(ip_address=ip, snmp_community=community, status='active')
            db.session.add(device)
            db.session.commit()
            return redirect(url_for('index'))
        else:
            return jsonify({'error': 'Could not connect to device via SNMP'}), 400
            
    except ValueError:
        return jsonify({'error': 'Invalid IP address'}), 400

@app.route('/scan_range', methods=['POST'])
def scan_range():
    ip_range = request.form.get('ip_range')
    community = request.form.get('snmp_community', 'public')
    
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        found_devices = []
        
        for ip in network.hosts():
            if scan_ip(str(ip), community):
                device = Device(ip_address=str(ip), snmp_community=community, status='active')
                db.session.add(device)
                found_devices.append(str(ip))
        
        db.session.commit()
        return jsonify({'message': f'Found {len(found_devices)} devices', 'devices': found_devices})
        
    except ValueError:
        return jsonify({'error': 'Invalid IP range'}), 400

@app.route('/check_status/<int:device_id>')
def check_status(device_id):
    device = Device.query.get_or_404(device_id)
    status = check_device_status(device.ip_address, device.snmp_community)
    
    device.status = 'active' if status else 'inactive'
    device.last_checked = datetime.utcnow()
    db.session.commit()
    
    return redirect(url_for('index'))

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

if __name__ == '__main__':
    app.run(debug=True) 