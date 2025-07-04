# Settings
#!/usr/bin/env python3
"""
Configuración central para Huawei Cloud Security Assessment
"""

import os
from datetime import datetime
from pathlib import Path
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    # dotenv es opcional; continuar si no está disponible
    pass

# Credenciales - NUNCA hardcodear valores reales
HUAWEI_ACCESS_KEY = os.getenv('HUAWEI_ACCESS_KEY')
HUAWEI_SECRET_KEY = os.getenv('HUAWEI_SECRET_KEY')
HUAWEI_PROJECT_ID = os.getenv('HUAWEI_PROJECT_ID')
HUAWEI_DOMAIN_ID = os.getenv('HUAWEI_DOMAIN_ID')

# Validar que las credenciales estén configuradas
if not all([HUAWEI_ACCESS_KEY, HUAWEI_SECRET_KEY]):
    print("WARNING: Credenciales de Huawei Cloud no configuradas.")
    print("Por favor, configure las variables en el archivo .env")

'''
# Regiones a evaluar
REGIONS = [
    'la-south-2',      # Santiago
    'sa-argentina-1',  # Buenos Aires
    'ap-southeast-1',  # Hong Kong
    'ap-southeast-2',  # Bangkok
    'ap-southeast-3',  # Singapore
]
'''
REGIONS = [
    'LA-Santiago',      # Santiago
    'LA-Buenos Aires1',     # Buenos Aires  
    'CN-Hong Kong',      # Hong Kong
    'AP-Bangkok',  # Bangkok
    'AP-Singapore',  # Singapore
]
				

# Región principal
#PRIMARY_REGION = os.getenv('HUAWEI_PRIMARY_REGION', 'sa-argentina-1')
PRIMARY_REGION = os.getenv('HUAWEI_PRIMARY_REGION', 'sa-argentina-1')

# Directorios
BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / 'output'
LOGS_DIR = BASE_DIR / 'logs'
REPORTS_DIR = BASE_DIR / 'reports'

# Crear directorios si no existen
for directory in [OUTPUT_DIR, LOGS_DIR, REPORTS_DIR]:
    directory.mkdir(exist_ok=True)

# Configuración de logs
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Configuración de reportes
REPORT_TIMESTAMP = datetime.now().strftime('%Y%m%d_%H%M%S')
REPORT_PREFIX = 'security_assessment'

# Umbrales de severidad
SEVERITY_THRESHOLDS = {
    'CRITICAL': 9.0,  # CVSS >= 9.0
    'HIGH': 7.0,      # CVSS >= 7.0
    'MEDIUM': 4.0,    # CVSS >= 4.0
    'LOW': 0.1        # CVSS >= 0.1
}

# Configuración de timeout para API calls
API_TIMEOUT = 30  # segundos
MAX_RETRIES = 3

# Configuración de batch processing
BATCH_SIZE = 50  # Procesar recursos en lotes de 50

# Filtros de exclusión (recursos que no se deben evaluar)
EXCLUDED_RESOURCE_TAGS = [
    'Environment:Test',
    'SecurityAssessment:Skip'
]

# Configuración de compliance
COMPLIANCE_FRAMEWORKS = [
    'CIS_Huawei_Cloud_1.1',
    'ISO_27001_2022',
    'NIST_CSF_2.0'
]

# Configuración de notificaciones
NOTIFICATION_WEBHOOK = os.getenv('NOTIFICATION_WEBHOOK')
NOTIFICATION_EMAIL = os.getenv('NOTIFICATION_EMAIL')

# Cliente info
CLIENT_NAME = "Camuzzi Gas Pampeana S.A."
ASSESSMENT_VERSION = "1.0"
ASSESSMENT_DATE = datetime.now().strftime('%Y-%m-%d')