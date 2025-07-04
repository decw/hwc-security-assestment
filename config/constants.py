# Constants
#!/usr/bin/env python3
"""
Constantes para el Assessment de Seguridad
"""

# Puertos críticos que no deben estar expuestos
CRITICAL_PORTS = {
    22: 'SSH',
    23: 'Telnet',
    135: 'RPC',
    139: 'NetBIOS',
    445: 'SMB',
    1433: 'SQL Server',
    1521: 'Oracle',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    5984: 'CouchDB',
    6379: 'Redis',
    7000: 'Cassandra',
    7001: 'Cassandra',
    8020: 'Hadoop',
    8086: 'InfluxDB',
    9042: 'Cassandra',
    9160: 'Cassandra',
    9200: 'Elasticsearch',
    9300: 'Elasticsearch',
    11211: 'Memcached',
    27017: 'MongoDB',
    27018: 'MongoDB',
    27019: 'MongoDB',
    50070: 'Hadoop'
}

# Protocolos inseguros
INSECURE_PROTOCOLS = [
    'HTTP',
    'FTP',
    'Telnet',
    'SNMPv1',
    'SNMPv2',
    'SSLv2',
    'SSLv3',
    'TLSv1.0'
]

# Algoritmos de cifrado débiles
WEAK_CIPHERS = [
    'DES',
    '3DES',
    'RC4',
    'MD5',
    'SHA1'
]

# Tamaños mínimos de clave
MIN_KEY_SIZES = {
    'RSA': 2048,
    'DSA': 2048,
    'ECDSA': 256,
    'AES': 128
}

# Políticas de contraseña mínimas
PASSWORD_POLICY = {
    'min_length': 12,
    'require_uppercase': True,
    'require_lowercase': True,
    'require_numbers': True,
    'require_special': True,
    'max_age_days': 90,
    'min_age_days': 1,
    'history_count': 12,
    'lockout_attempts': 5,
    'lockout_duration_mins': 30
}

# Configuración de MFA
MFA_REQUIREMENTS = {
    'admin_users': 'mandatory',
    'privileged_users': 'mandatory',
    'standard_users': 'recommended',
    'service_accounts': 'conditional'
}

# Retención mínima de logs (días)
LOG_RETENTION_REQUIREMENTS = {
    'security_logs': 365,
    'audit_logs': 365,
    'access_logs': 90,
    'application_logs': 30,
    'performance_logs': 30
}

# Configuración de backup
BACKUP_REQUIREMENTS = {
    'critical_systems': {
        'frequency': 'daily',
        'retention_days': 90,
        'cross_region': True,
        'encryption': 'mandatory',
        'test_frequency': 'monthly'
    },
    'important_systems': {
        'frequency': 'daily',
        'retention_days': 30,
        'cross_region': True,
        'encryption': 'mandatory',
        'test_frequency': 'quarterly'
    },
    'standard_systems': {
        'frequency': 'weekly',
        'retention_days': 30,
        'cross_region': False,
        'encryption': 'recommended',
        'test_frequency': 'annually'
    }
}

# Métricas de disponibilidad objetivo
AVAILABILITY_TARGETS = {
    'critical': {
        'availability': 99.99,  # %
        'rpo_minutes': 15,
        'rto_minutes': 60
    },
    'important': {
        'availability': 99.9,
        'rpo_minutes': 60,
        'rto_minutes': 240
    },
    'standard': {
        'availability': 99.0,
        'rpo_minutes': 1440,  # 24 hours
        'rto_minutes': 2880   # 48 hours
    }
}

# Tags de clasificación de datos
DATA_CLASSIFICATION_TAGS = {
    'public': 'Classification:Public',
    'internal': 'Classification:Internal',
    'confidential': 'Classification:Confidential',
    'secret': 'Classification:Secret'
}

# Servicios críticos de Huawei Cloud
CRITICAL_SERVICES = [
    'IAM',
    'ECS',
    'EVS', 
    'VPC',
    'OBS',
    'KMS',
    'HSS',
    'WAF'
]

# Mapeo de severidades
SEVERITY_MAPPING = {
    'CRITICAL': {'icon': '🔴', 'priority': 1},
    'HIGH': {'icon': '🟠', 'priority': 2},
    'MEDIUM': {'icon': '🟡', 'priority': 3},
    'LOW': {'icon': '🟢', 'priority': 4},
    'INFO': {'icon': '🔵', 'priority': 5}
}