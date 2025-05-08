from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import ipaddress
from snmp_operations import scan_ip, check_device_status

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///devices.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(15), unique=True, nullable=False)
    name = db.Column(db.String(100))
    status = db.Column(db.String(20))
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)
    snmp_community = db.Column(db.String(50), default='public')

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    devices = Device.query.all()
    return render_template('index.html', devices=devices)

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

if __name__ == '__main__':
    app.run(debug=True) 