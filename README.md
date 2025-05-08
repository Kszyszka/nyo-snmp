# SNMP Network Monitor

A Flask-based web application for monitoring network devices using SNMP. This application allows you to:
- Add individual devices for monitoring
- Scan IP ranges for SNMP-enabled devices
- Monitor device status in real-time
- View device information and status history

## Requirements

- Python 3.7+
- Flask
- pysnmp
- SQLAlchemy
- Other dependencies listed in requirements.txt

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd snmp-monitor
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Open your web browser and navigate to `http://localhost:5000`

3. Use the web interface to:
   - Add individual devices by IP address
   - Scan IP ranges using CIDR notation (e.g., 192.168.1.0/24)
   - Monitor device status
   - View device information

## Features

- Add individual devices for monitoring
- Scan IP ranges for SNMP-enabled devices
- Real-time status monitoring
- Device information display
- Status history tracking
- Modern web interface

## Security Notes

- The default SNMP community string is set to 'public'
- It's recommended to change the community string to a more secure value
- Consider implementing authentication for the web interface in production

## License

This project is licensed under the MIT License - see the LICENSE file for details.
