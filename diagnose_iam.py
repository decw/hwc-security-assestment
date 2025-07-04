#!/usr/bin/env python3
"""
Script de diagnóstico para problemas de importación de IAMCollector
"""

import sys
import traceback

print("=== Diagnóstico de IAMCollector ===\n")

# 1. Verificar path de Python
print("1. Python Path:")
for path in sys.path:
    print(f"  - {path}")

# 2. Intentar importar dependencias paso a paso
print("\n2. Verificando dependencias:")

# Verificar huaweicloudsdkcore
try:
    from huaweicloudsdkcore.auth.credentials import GlobalCredentials
    print("  ✅ huaweicloudsdkcore.auth.credentials - OK")
except ImportError as e:
    print(f"  ❌ huaweicloudsdkcore.auth.credentials - ERROR: {e}")

# Verificar huaweicloudsdkiam
try:
    import huaweicloudsdkiam
    print(f"  ✅ huaweicloudsdkiam - OK (version: {getattr(huaweicloudsdkiam, '__version__', 'unknown')})")
except ImportError as e:
    print(f"  ❌ huaweicloudsdkiam - ERROR: {e}")

# Verificar huaweicloudsdkiam.v3
try:
    from huaweicloudsdkiam import v3
    print("  ✅ huaweicloudsdkiam.v3 - OK")
except ImportError as e:
    print(f"  ❌ huaweicloudsdkiam.v3 - ERROR: {e}")

# Verificar clases específicas
try:
    from huaweicloudsdkiam.v3 import IamClient
    print("  ✅ IamClient - OK")
except ImportError as e:
    print(f"  ❌ IamClient - ERROR: {e}")

# Verificar utils y config
try:
    from utils.logger import SecurityLogger
    print("  ✅ utils.logger - OK")
except ImportError as e:
    print(f"  ❌ utils.logger - ERROR: {e}")

try:
    from config.settings import HUAWEI_ACCESS_KEY, HUAWEI_SECRET_KEY
    print("  ✅ config.settings - OK")
except ImportError as e:
    print(f"  ❌ config.settings - ERROR: {e}")

try:
    from config.constants import PASSWORD_POLICY, MFA_REQUIREMENTS
    print("  ✅ config.constants - OK")
except ImportError as e:
    print(f"  ❌ config.constants - ERROR: {e}")

# 3. Intentar importar IAMCollector completo
print("\n3. Intentando importar IAMCollector:")
try:
    from collectors.iam_collector import IAMCollector
    print("  ✅ IAMCollector importado exitosamente")
    
    # Verificar que se puede instanciar
    try:
        collector = IAMCollector()
        print("  ✅ IAMCollector instanciado exitosamente")
    except Exception as e:
        print(f"  ❌ Error al instanciar IAMCollector: {e}")
        traceback.print_exc()
        
except ImportError as e:
    print(f"  ❌ Error al importar IAMCollector: {e}")
    print("\n  Traceback completo:")
    traceback.print_exc()

# 4. Verificar estructura de archivos
print("\n4. Verificando estructura de archivos:")
import os

files_to_check = [
    'collectors/__init__.py',
    'collectors/iam_collector.py',
    'utils/__init__.py',
    'utils/logger.py',
    'config/__init__.py',
    'config/settings.py',
    'config/constants.py'
]

for file in files_to_check:
    if os.path.exists(file):
        print(f"  ✅ {file} - Existe")
    else:
        print(f"  ❌ {file} - NO EXISTE")

print("\n=== Fin del diagnóstico ===")