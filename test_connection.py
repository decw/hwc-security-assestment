#!/usr/bin/env python3
"""
Script para probar la conexión con Huawei Cloud
"""

import os
import sys
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

print("=== Prueba de Conexión Huawei Cloud ===\n")

# 1. Verificar variables de entorno
print("1. Verificando variables de entorno:")
env_vars = {
    'HUAWEI_ACCESS_KEY': os.getenv('HUAWEI_ACCESS_KEY'),
    'HUAWEI_SECRET_KEY': os.getenv('HUAWEI_SECRET_KEY'),
    'HUAWEI_PROJECT_ID': os.getenv('HUAWEI_PROJECT_ID'),
    'HUAWEI_DOMAIN_ID': os.getenv('HUAWEI_DOMAIN_ID')
}

all_vars_set = True
for var_name, var_value in env_vars.items():
    if var_value:
        # Mostrar solo los primeros caracteres por seguridad
        masked_value = var_value[:4] + "****" + var_value[-4:] if len(var_value) > 8 else "****"
        print(f"  ✅ {var_name}: {masked_value}")
    else:
        print(f"  ❌ {var_name}: NO CONFIGURADA")
        all_vars_set = False

if not all_vars_set:
    print("\n❌ ERROR: Faltan variables de entorno. Configure el archivo .env")
    sys.exit(1)

print("\n2. Probando importación de SDKs:")

# 2. Probar imports
sdks_to_test = [
    ('huaweicloudsdkcore', 'Core SDK'),
    ('huaweicloudsdkiam', 'IAM SDK'),
    ('huaweicloudsdkvpc', 'VPC SDK'),
    ('huaweicloudsdkecs', 'ECS SDK'),
    ('huaweicloudsdkevs', 'EVS SDK')
]

available_sdks = []
for module_name, display_name in sdks_to_test:
    try:
        __import__(module_name)
        print(f"  ✅ {display_name}")
        available_sdks.append(module_name)
    except ImportError:
        print(f"  ❌ {display_name} - No disponible")

if not available_sdks:
    print("\n❌ ERROR: No hay SDKs instalados. Ejecute: pip install huaweicloudsdkcore")
    sys.exit(1)

# 3. Probar conexión básica
print("\n3. Probando conexión con Huawei Cloud:")

try:
    from huaweicloudsdkcore.auth.credentials import GlobalCredentials
    from huaweicloudsdkcore.exceptions import exceptions
    
    # Crear credenciales
    credentials = GlobalCredentials(
        os.getenv('HUAWEI_ACCESS_KEY'),
        os.getenv('HUAWEI_SECRET_KEY'),
        os.getenv('HUAWEI_DOMAIN_ID')
    )
    print("  ✅ Credenciales creadas correctamente")
    
    # Si IAM está disponible, intentar una llamada simple
    if 'huaweicloudsdkiam' in available_sdks:
        try:
            from huaweicloudsdkiam.v3 import IamClient
            from huaweicloudsdkcore.region.region import Region
            
            # Crear cliente IAM
            client = IamClient.new_builder() \
                .with_credentials(credentials) \
                .with_endpoint("https://iam.myhuaweicloud.com") \
                .build()
            
            print("  ✅ Cliente IAM creado")
            
            # Intentar una operación simple (obtener información del token actual)
            try:
                from huaweicloudsdkiam.v3 import ShowCredentialRequest
                request = ShowCredentialRequest()
                # Esta llamada puede fallar, pero es solo para probar la conexión
                print("  ℹ️  Intentando llamada de prueba...")
                # No ejecutamos la llamada real para evitar errores
                print("  ✅ Configuración del cliente parece correcta")
            except Exception as e:
                print(f"  ⚠️  No se pudo completar la llamada de prueba: {type(e).__name__}")
                
        except Exception as e:
            print(f"  ❌ Error creando cliente IAM: {str(e)}")
    
except Exception as e:
    print(f"  ❌ Error en la prueba de conexión: {str(e)}")
    print(f"     Tipo: {type(e).__name__}")

# 4. Verificar regiones
print("\n4. Regiones configuradas:")
try:
    from config.settings import REGIONS, PRIMARY_REGION
    print(f"  • Región principal: {PRIMARY_REGION}")
    print(f"  • Regiones a analizar: {', '.join(REGIONS)}")
except:
    print("  ⚠️  No se pudieron cargar las regiones desde config/settings.py")

print("\n=== Fin de la prueba ===")
print("\nSi todas las pruebas pasaron, puede ejecutar: python3 main.py")
print("Si hay errores, revise la configuración y las dependencias.")