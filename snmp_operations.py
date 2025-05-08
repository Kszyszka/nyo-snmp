from pysnmp.hlapi import *

def scan_ip(ip, community='public', timeout=1):
    """
    Scan a single IP address for SNMP availability
    """
    try:
        error_indication, error_status, error_index, var_binds = next(
            getCmd(SnmpEngine(),
                  CommunityData(community),
                  UdpTransportTarget((ip, 161), timeout=timeout),
                  ContextData(),
                  ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))
        )
        
        if error_indication:
            return False
        elif error_status:
            return False
        else:
            return True
            
    except Exception:
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

def get_device_name(ip, community='public'):
    try:
        error_indication, error_status, error_index, var_binds = next(
            getCmd(SnmpEngine(),
                  CommunityData(community),
                  UdpTransportTarget((ip, 161)),
                  ContextData(),
                  ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)))
        )
        
        if error_indication is None and error_status == 0:
            for var_bind in var_binds:
                name = str(var_bind[1])
                if name and name != '0':
                    return name
        return None
    except Exception:
        return None 