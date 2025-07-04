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



# Mapeo exacto de regiones según el inventario de CAMUZZI
REGION_PROJECT_MAPPING = {
    'ap-southeast-2': '07c695df5880251f2f9cc01383f48cb3',  # AP-Bangkok
    'ap-southeast-3': '07c695df700026022f20c013b5a9f7bb',  # AP-Singapore
    'cn-east-3': '07c695df268010fe2f56c013e33fa1d1',      # CN East-Shanghai1
    'cn-north-4': '07c695df17000f082fffc0131753d0c1',     # CN North-Beijing4
    'ap-southeast-1': '07c695df4d0026fe2f59c0131f659a3b',  # CN-Hong Kong
    'sa-argentina-1': '4b941a5dca294bedab5e907bd7f2bd08',  # LA-Buenos Aires1
    'la-south-2': '07c695df6c0025232fe4c013d2eb1218',      # LA-Santiago
    'sa-brazil-1': '07c695df5b8010fd2f83c013996e3277'      # LA-Sao Paulo1
}



# Regiones a evaluar (basado en el inventario donde hay recursos)
REGIONS_TO_ASSESS = [
    'la-south-2',      # LA-Santiago (50 recursos)
    'sa-argentina-1',  # LA-Buenos Aires1 (369 recursos)
    'ap-southeast-1',  # CN-Hong Kong (6 recursos)
    'ap-southeast-3',  # AP-Singapore (2 recursos)
    'ap-southeast-2'   # AP-Bangkok (4 recursos)
]


# Nombres descriptivos de regiones para reportes
REGION_DISPLAY_NAMES = {
    'ap-southeast-2': 'AP-Bangkok',
    'ap-southeast-3': 'AP-Singapore',
    'cn-east-3': 'CN East-Shanghai1',
    'cn-north-4': 'CN North-Beijing4',
    'ap-southeast-1': 'CN-Hong Kong',
    'sa-argentina-1': 'LA-Buenos Aires1',
    'la-south-2': 'LA-Santiago',
    'sa-brazil-1': 'LA-Sao Paulo1'
}	


# Usar REGIONS_TO_ASSESS como REGIONS principal
REGIONS = REGIONS_TO_ASSESS


# Región principal (Buenos Aires tiene más recursos)
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
CLIENT_NAME = "CCGP S.A."
ASSESSMENT_VERSION = "1.0"
ASSESSMENT_DATE = datetime.now().strftime('%Y-%m-%d')