from pysnmp.hlapi import *
import logging
import subprocess
import platform
import concurrent.futures
import ipaddress

logger = logging.getLogger(__name__)

def ping(ip, timeout=1):
    """
    Ping an IP address to check if it's active
    """
    try:
        # Different ping commands for different OS
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-w', str(timeout * 1000), str(ip)]
        
        result = subprocess.run(command, 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE, 
                              timeout=timeout + 1)
        
        return result.returncode == 0
    except Exception as e:
        logger.debug(f"Error pinging {ip}: {str(e)}")
        return False

def scan_ip(ip, community='public', timeout=1):
    """
    Scan a single IP address for SNMP availability
    """
    try:
        error_indication, error_status, error_index, var_binds = next(
            getCmd(SnmpEngine(),
                  CommunityData(community),
                  UdpTransportTarget((ip, 161), timeout=timeout, retries=0),
                  ContextData(),
                  ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))
        )
        
        if error_indication:
            logger.debug(f"SNMP error for {ip}: {error_indication}")
            return False
        elif error_status:
            logger.debug(f"SNMP error for {ip}: {error_status}")
            return False
        else:
            return True
            
    except Exception as e:
        logger.debug(f"Error scanning {ip}: {str(e)}")
        return False

def check_device_status(ip, community='public', timeout=1):
    """
    Check if a device is responding to SNMP queries
    """
    return scan_ip(ip, community, timeout)

def get_system_info(ip, community='public'):
    """
    Get basic system information from a device
    """
    try:
        error_indication, error_status, error_index, var_binds = next(
            getCmd(SnmpEngine(),
                  CommunityData(community),
                  UdpTransportTarget((ip, 161)),
                  ContextData(),
                  ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
                  ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)),
                  ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysLocation', 0)))
        )
        
        if error_indication:
            return None
        elif error_status:
            return None
        else:
            return {
                'description': str(var_binds[0][1]),
                'name': str(var_binds[1][1]),
                'location': str(var_binds[2][1])
            }
            
    except Exception:
        return None

def get_device_name(ip, community='public', timeout=1):
    """
    Get device name via SNMP
    """
    try:
        error_indication, error_status, error_index, var_binds = next(
            getCmd(SnmpEngine(),
                  CommunityData(community),
                  UdpTransportTarget((ip, 161), timeout=timeout, retries=0),
                  ContextData(),
                  ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)))
        )
        
        if error_indication is None and error_status == 0:
            for var_bind in var_binds:
                name = str(var_bind[1])
                if name and name != '0':
                    return name
        return None
    except Exception as e:
        logger.debug(f"Error getting device name for {ip}: {str(e)}")
        return None

def find_active_ips(ip_range, max_workers=50):
    """
    Find all active IPs in a range using ping
    """
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        active_ips = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(ping, str(ip)): str(ip) for ip in network.hosts()}
            
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    if future.result():
                        active_ips.append(ip)
                except Exception as e:
                    logger.error(f"Error checking {ip}: {str(e)}")
        
        return active_ips
    except Exception as e:
        logger.error(f"Error finding active IPs: {str(e)}")
        return [] 