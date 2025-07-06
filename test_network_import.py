#!/usr/bin/env python3
"""Test de importación de NetworkCollector"""

import sys
import traceback

print("=== Test de Importación NetworkCollector ===\n")

# Intentar importar con información detallada del error
try:
    from collectors.network_collector import NetworkCollector
    print("✅ NetworkCollector importado correctamente")
except ImportError as e:
    print(f"❌ Error de importación: {e}")
    print("\nTraceback completo:")
    traceback.print_exc()
except Exception as e:
    print(f"❌ Error inesperado: {type(e).__name__}: {e}")
    print("\nTraceback completo:")
    traceback.print_exc()

# Verificar dependencias
print("\n=== Verificando Dependencias ===")
dependencies = [
    'huaweicloudsdkvpc.v2',
    'huaweicloudsdkecs.v2',
    'ipaddress'
]

for dep in dependencies:
    try:
        __import__(dep)
        print(f"✅ {dep}")
    except ImportError:
        print(f"❌ {dep} - NO INSTALADO")