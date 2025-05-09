from flask import Flask, render_template, request, jsonify, redirect, url_for, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone, timedelta
import ipaddress
from snmp_operations import scan_ip, check_device_status, get_device_name, find_active_ips, get_system_metrics
import threading
import time
import json
import os
import logging
import queue
from flask_sse import sse

# Konfiguracja logowania
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),  # Wyjście do konsoli
        logging.FileHandler('app.log')  # Wyjście do pliku
    ]
)
logger = logging.getLogger(__name__)

# Ustaw poziom logowania Flask na INFO
logging.getLogger('werkzeug').setLevel(logging.INFO)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///devices.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Ścieżka do pliku konfiguracyjnego
CONFIG_FILE = 'config.json'

# Domyślna konfiguracja
DEFAULT_CONFIG = {
    'check_interval': 300  # 5 minut w sekundach
}

# Zmienne globalne
current_check_interval = None
last_check_time = datetime.now(timezone.utc)
checking_active = True
check_cycle_complete = False
interval_changed = False

# Globalna kolejka postępu dla aktualizacji skanowania
scan_progress_queue = queue.Queue()

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return DEFAULT_CONFIG

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f)

# Inicjalizacja current_check_interval z konfiguracji
config = load_config()
current_check_interval = config['check_interval']
logger.info(f"Zainicjalizowano interwał sprawdzania na {current_check_interval} sekund z konfiguracji")

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(15), unique=True, nullable=False)
    name = db.Column(db.String(100))
    status = db.Column(db.String(20))
    last_checked = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    snmp_community = db.Column(db.String(50), default='public')
    uptime = db.Column(db.String(50))
    cpu_usage = db.Column(db.Float)
    memory_used = db.Column(db.Integer)  # w MB
    memory_total = db.Column(db.Integer)  # w MB

def check_all_devices():
    """Sprawdza status wszystkich urządzeń w bazie danych"""
    global last_check_time, check_cycle_complete
    logger.info("[check_all_devices] Rozpoczynanie cyklu sprawdzania urządzeń")
    with app.app_context():
        devices = Device.query.all()
        logger.info(f"[check_all_devices] Sprawdzanie {len(devices)} urządzeń")
        
        # Ustaw czas rozpoczęcia sprawdzania
        check_start_time = get_local_time()
        
        for device in devices:
            try:
                # Sprawdź czy urządzenie odpowiada na SNMP
                is_active = check_device_status(device.ip_address, device.snmp_community)
                device.status = 'active' if is_active else 'inactive'
                logger.info(f"[check_all_devices] Status urządzenia {device.ip_address}: {device.status}")
                
                # Jeśli urządzenie jest aktywne, spróbuj pobrać jego nazwę i metryki
                if is_active:
                    # Pobierz nazwę urządzenia jeśli jest nieznana
                    if device.name == 'Unknown':
                        try:
                            device_name = get_device_name(device.ip_address, device.snmp_community)
                            if device_name:
                                device.name = device_name
                                logger.info(f"[check_all_devices] Zaktualizowano nazwę urządzenia dla {device.ip_address}: {device_name}")
                        except Exception as e:
                            logger.error(f"[check_all_devices] Błąd pobierania nazwy urządzenia dla {device.ip_address}: {str(e)}")
                    
                    # Pobierz metryki systemowe
                    try:
                        metrics = get_system_metrics(device.ip_address, device.snmp_community)
                        if metrics:
                            device.uptime = metrics.get('uptime')
                            device.cpu_usage = metrics.get('cpu_usage')
                            device.memory_used = metrics.get('memory_used')
                            device.memory_total = metrics.get('memory_total')
                            logger.info(f"[check_all_devices] Zaktualizowano metryki dla {device.ip_address}")
                    except Exception as e:
                        logger.error(f"[check_all_devices] Błąd pobierania metryk dla {device.ip_address}: {str(e)}")
                
                device.last_checked = check_start_time
                db.session.commit()
            except Exception as e:
                logger.error(f"[check_all_devices] Błąd sprawdzania urządzenia {device.ip_address}: {str(e)}")
                device.status = 'inactive'
                device.last_checked = check_start_time
                db.session.commit()
        
        # Aktualizuj czas ostatniego sprawdzenia i ustaw flagę zakończenia cyklu
        last_check_time = check_start_time
        check_cycle_complete = True
        logger.info(f"[check_all_devices] Zakończono cykl sprawdzania urządzeń o {last_check_time}, check_cycle_complete ustawiono na True")
        # Dodaj małe opóźnienie aby upewnić się, że flaga zostanie zauważona
        time.sleep(0.1)

def background_checker():
    """Wątek w tle, który okresowo sprawdza wszystkie urządzenia"""
    global current_check_interval
    logger.info(f"[background_checker] Uruchomiono z interwałem: {current_check_interval} sekund")
    while True:
        try:
            logger.info("[background_checker] Rozpoczynanie nowego cyklu sprawdzania")
            check_all_devices()
            logger.info(f"[background_checker] Cykl sprawdzania zakończony, oczekiwanie {current_check_interval} sekund")
            # Śpij w mniejszych interwałach aby być bardziej responsywnym
            for _ in range(current_check_interval):
                time.sleep(1)
        except Exception as e:
            logger.error(f"[background_checker] Błąd: {str(e)}")
            time.sleep(30)  # Poczekaj 30 sekund przed ponowną próbą w przypadku błędu

# Uruchom wątek sprawdzania w tle
checking_thread = threading.Thread(target=background_checker, daemon=True)
checking_thread.start()

with app.app_context():
    db.create_all()

def get_local_time():
    """Konwertuje czas UTC na czas lokalny"""
    return datetime.now(timezone.utc).astimezone()

@app.route('/')
def index():
    devices = Device.query.all()
    config = load_config()
    return render_template('index.html', 
                         devices=devices, 
                         check_interval=config['check_interval'],
                         last_check_time=get_local_time())

@app.route('/get_last_check_time')
def get_last_check_time():
    global last_check_time, check_cycle_complete, interval_changed
    logger.info(f"[get_last_check_time] Wywołano - Ostatnie sprawdzenie: {last_check_time}, Cykl zakończony: {check_cycle_complete}, Interwał zmieniony: {interval_changed}")
    
    # Zapisz aktualny stan check_cycle_complete przed resetowaniem
    current_cycle_complete = check_cycle_complete
    
    # Oblicz czas od ostatniego sprawdzenia
    current_time = get_local_time()
    time_since_last_check = (current_time - last_check_time).total_seconds()
    
    # Jeśli sprawdzenie zostało zakończone w ciągu ostatnich 10 sekund, uznaj je za zakończone
    if time_since_last_check < 10 and not current_cycle_complete:
        logger.info(f"[get_last_check_time] Wykryto niedawne sprawdzenie ({time_since_last_check:.1f} sekund temu)")
        current_cycle_complete = True
    
    response = {
        'last_check_time': current_time.strftime('%Y-%m-%d %H:%M:%S'),
        'check_cycle_complete': current_cycle_complete,
        'interval_changed': interval_changed
    }
    
    # Resetuj flagi po zapisaniu ich w odpowiedzi
    check_cycle_complete = False
    interval_changed = False
    
    logger.info(f"[get_last_check_time] Odpowiedź: {response}")
    return jsonify(response)

@app.route('/update_check_interval', methods=['POST'])
def update_check_interval():
    global current_check_interval, interval_changed
    try:
        interval = int(request.form.get('interval', 300))
        if interval < 30:  # Minimum 30 sekund
            return jsonify({'error': 'Interwał musi wynosić co najmniej 30 sekund'}), 400
            
        config = load_config()
        config['check_interval'] = interval
        save_config(config)
        
        # Aktualizuj globalną zmienną interwału natychmiast
        current_check_interval = interval
        interval_changed = True
        logger.info(f"Zaktualizowano interwał sprawdzania na {interval} sekund")
        
        return jsonify({'message': 'Interwał sprawdzania zaktualizowany pomyślnie'})
    except ValueError:
        return jsonify({'error': 'Nieprawidłowa wartość interwału'}), 400

@app.route('/add_device', methods=['POST'])
def add_device():
    ip = request.form.get('ip_address')
    community = request.form.get('snmp_community', 'public')
    
    try:
        # Sprawdź poprawność adresu IP
        ipaddress.ip_address(ip)
        
        # Sprawdź czy urządzenie istnieje
        existing_device = Device.query.filter_by(ip_address=ip).first()
        if existing_device:
            return jsonify({'error': 'Urządzenie już istnieje'}), 400
        
        # Spróbuj przeskanować urządzenie
        if scan_ip(ip, community):
            # Spróbuj pobrać nazwę urządzenia
            name = None
            try:
                name = get_device_name(ip, community)
            except Exception as e:
                logger.error(f"Błąd pobierania nazwy urządzenia: {str(e)}")
            
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
            return jsonify({'error': 'Nie można połączyć się z urządzeniem przez SNMP'}), 400
            
    except ValueError:
        return jsonify({'error': 'Nieprawidłowy adres IP'}), 400

def scan_range_worker(ip_range, community):
    # Utwórz kontekst aplikacji dla wątku w tle
    with app.app_context():
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            total_ips = sum(1 for _ in network.hosts())
            
            # Znajdź aktywne adresy IP
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
                    # Sprawdź czy urządzenie już istnieje
                    existing_device = Device.query.filter_by(ip_address=ip).first()
                    if existing_device:
                        continue
                        
                    # Spróbuj przeskanować urządzenie
                    if scan_ip(ip, community):
                        # Spróbuj pobrać nazwę urządzenia
                        name = None
                        try:
                            name = get_device_name(ip, community)
                        except Exception as e:
                            logger.error(f"Błąd pobierania nazwy urządzenia dla {ip}: {str(e)}")
                        
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
                    logger.error(f"Błąd skanowania {ip}: {str(e)}")
                    continue
            
            try:
                db.session.commit()
                scan_progress_queue.put({
                    'type': 'complete',
                    'message': f'Znaleziono {len(found_devices)} nowych urządzeń',
                    'devices': found_devices,
                    'total_ips': total_ips,
                    'active_ips': len(active_ips),
                    'scanned': scanned_count
                })
            except Exception as e:
                logger.error(f"Błąd bazy danych: {str(e)}")
                db.session.rollback()
                scan_progress_queue.put({
                    'type': 'error',
                    'error': f'Błąd bazy danych: {str(e)}'
                })
                
        except Exception as e:
            logger.error(f"Nieoczekiwany błąd w scan_range_worker: {str(e)}")
            scan_progress_queue.put({
                'type': 'error',
                'error': f'Nieoczekiwany błąd: {str(e)}'
            })

@app.route('/scan_range', methods=['POST'])
def scan_range():
    try:
        ip_range = request.form.get('ip_range')
        community = request.form.get('snmp_community', 'public')
        
        if not ip_range:
            return jsonify({'error': 'Zakres IP jest wymagany'}), 400
            
        # Rozpocznij skanowanie w wątku w tle
        thread = threading.Thread(target=scan_range_worker, args=(ip_range, community))
        thread.daemon = True
        thread.start()
        
        return jsonify({'message': 'Skanowanie rozpoczęte'})
            
    except Exception as e:
        logger.error(f"Błąd rozpoczynania skanowania: {str(e)}")
        return jsonify({'error': f'Błąd rozpoczynania skanowania: {str(e)}'}), 500

@app.route('/scan_progress')
def scan_progress():
    def generate():
        while True:
            try:
                # Pobierz aktualizację postępu z kolejki
                progress = scan_progress_queue.get(timeout=30)
                yield f"data: {json.dumps(progress)}\n\n"
                
                # Jeśli skanowanie jest zakończone lub wystąpił błąd, zatrzymaj wysyłanie aktualizacji
                if progress['type'] in ['complete', 'error']:
                    break
                    
            except queue.Empty:
                # Brak aktualizacji przez 30 sekund, wyślij heartbeat
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
                
    return Response(generate(), mimetype='text/event-stream')

@app.route('/check_status/<int:device_id>')
def check_status(device_id):
    """Sprawdza status konkretnego urządzenia"""
    device = Device.query.get_or_404(device_id)
    try:
        is_active = check_device_status(device.ip_address, device.snmp_community)
        device.status = 'active' if is_active else 'inactive'
        
        # Jeśli urządzenie jest aktywne, spróbuj pobrać jego nazwę i metryki
        if is_active:
            # Pobierz nazwę urządzenia jeśli jest nieznana
            if device.name == 'Unknown':
                try:
                    device_name = get_device_name(device.ip_address, device.snmp_community)
                    if device_name:
                        device.name = device_name
                except Exception as e:
                    logging.error(f"Błąd pobierania nazwy urządzenia dla {device.ip_address}: {str(e)}")
            
            # Pobierz metryki systemowe
            try:
                metrics = get_system_metrics(device.ip_address, device.snmp_community)
                if metrics:
                    device.uptime = metrics.get('uptime')
                    device.cpu_usage = metrics.get('cpu_usage')
                    device.memory_used = metrics.get('memory_used')
                    device.memory_total = metrics.get('memory_total')
            except Exception as e:
                logging.error(f"Błąd pobierania metryk dla {device.ip_address}: {str(e)}")
        
        device.last_checked = get_local_time()
        db.session.commit()
        return jsonify({'status': 'success', 'message': f'Urządzenie {device.ip_address} jest {device.status}'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/delete_device/<int:device_id>', methods=['POST'])
def delete_device(device_id):
    device = Device.query.get_or_404(device_id)
    db.session.delete(device)
    db.session.commit()
    return jsonify({'message': 'Urządzenie zostało usunięte pomyślnie'})

@app.route('/delete_devices', methods=['POST'])
def delete_devices():
    device_ids = request.json.get('device_ids', [])
    if not device_ids:
        return jsonify({'error': 'Nie wybrano żadnych urządzeń'}), 400
    
    Device.query.filter(Device.id.in_(device_ids)).delete(synchronize_session=False)
    db.session.commit()
    return jsonify({'message': f'Pomyślnie usunięto {len(device_ids)} urządzeń'})

@app.route('/check_all_devices_now')
def check_all_devices_now():
    devices = Device.query.all()
    for device in devices:
        try:
            status = check_device_status(device.ip_address, device.snmp_community)
            device.status = 'active' if status else 'inactive'
            device.last_checked = get_local_time()
            
            # Spróbuj pobrać nazwę urządzenia jeśli status jest aktywny
            if status and (not device.name or device.name == 'Unknown'):
                try:
                    name = get_device_name(device.ip_address, device.snmp_community)
                    if name:
                        device.name = name
                except Exception as e:
                    logger.error(f"Błąd pobierania nazwy urządzenia: {str(e)}")
        except Exception as e:
            logger.error(f"Błąd sprawdzania urządzenia {device.ip_address}: {str(e)}")
            device.status = 'inactive'
            device.last_checked = get_local_time()
    
    db.session.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True) 