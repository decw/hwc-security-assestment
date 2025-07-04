#!/usr/bin/env python3
"""
Script para identificar qué clases están realmente disponibles en el SDK de IAM
"""

import sys
import inspect

print("=== Exploración del SDK de IAM ===\n")

# 1. Verificar si el módulo IAM está instalado
try:
    import huaweicloudsdkiam
    print(f"✅ huaweicloudsdkiam instalado - Versión: {getattr(huaweicloudsdkiam, '__version__', 'unknown')}")
except ImportError as e:
    print(f"❌ huaweicloudsdkiam NO instalado: {e}")
    sys.exit(1)

# 2. Explorar estructura del módulo
print("\n2. Estructura del módulo:")
try:
    import huaweicloudsdkiam.v3
    print("  ✅ huaweicloudsdkiam.v3 disponible")
    
    # Listar submódulos
    v3_attrs = dir(huaweicloudsdkiam.v3)
    print(f"  Atributos en v3: {', '.join([a for a in v3_attrs if not a.startswith('_')])}")
except ImportError as e:
    print(f"  ❌ Error: {e}")

# 3. Explorar el módulo model
print("\n3. Clases en huaweicloudsdkiam.v3.model:")
try:
    from huaweicloudsdkiam.v3 import model
    
    # Obtener todas las clases
    all_classes = []
    for name, obj in inspect.getmembers(model):
        if inspect.isclass(obj) and not name.startswith('_'):
            all_classes.append(name)
    
    print(f"  Total de clases encontradas: {len(all_classes)}")
    
    # Filtrar clases relevantes
    print("\n  Clases Request encontradas:")
    request_classes = [c for c in all_classes if 'Request' in c]
    for cls in sorted(request_classes):
        print(f"    - {cls}")
    
    print("\n  Clases Response encontradas:")
    response_classes = [c for c in all_classes if 'Response' in c]
    for cls in sorted(response_classes[:10]):  # Solo las primeras 10
        print(f"    - {cls}")
    if len(response_classes) > 10:
        print(f"    ... y {len(response_classes) - 10} más")
    
    print("\n  Clases con 'Keystone':")
    keystone_classes = [c for c in all_classes if 'Keystone' in c]
    for cls in sorted(keystone_classes):
        print(f"    - {cls}")
    
    print("\n  Clases con 'List':")
    list_classes = [c for c in all_classes if c.startswith('List')]
    for cls in sorted(list_classes[:10]):  # Solo las primeras 10
        print(f"    - {cls}")
    if len(list_classes) > 10:
        print(f"    ... y {len(list_classes) - 10} más")
        
except ImportError as e:
    print(f"  ❌ Error importando model: {e}")
except Exception as e:
    print(f"  ❌ Error explorando model: {e}")

# 4. Verificar clases específicas que intentamos usar
print("\n4. Verificación de clases específicas:")
classes_to_check = [
    'KeystoneListUsersRequest',
    'KeystoneListGroupsRequest',
    'ListUsersRequest',
    'ListGroupsRequest',
    'ListCustomPoliciesRequest',
    'ListPermanentAccessKeysRequest',
    'ShowUserMfaDeviceRequest',
    'ShowDomainPasswordPolicyRequest',
    'ListAgenciesRequest',
    'KeystoneListProjectPermissionsRequest'  # La que causa el error
]

for class_name in classes_to_check:
    try:
        exec(f"from huaweicloudsdkiam.v3.model import {class_name}")
        print(f"  ✅ {class_name}")
    except ImportError:
        print(f"  ❌ {class_name} - NO EXISTE")

# 5. Verificar el cliente
print("\n5. Verificación del cliente IAM:")
try:
    from huaweicloudsdkiam.v3 import IamClient
    print("  ✅ IamClient disponible")
    
    # Listar métodos del cliente
    print("\n  Métodos disponibles en IamClient:")
    methods = [m for m in dir(IamClient) if not m.startswith('_') and callable(getattr(IamClient, m))]
    
    # Métodos relevantes
    relevant_methods = [m for m in methods if any(keyword in m.lower() for keyword in ['list', 'show', 'create', 'delete', 'update'])]
    
    print(f"  Total métodos: {len(methods)}")
    print("\n  Métodos de listado:")
    list_methods = [m for m in methods if m.startswith('list') or 'list' in m]
    for method in sorted(list_methods):
        print(f"    - {method}")
    
    print("\n  Métodos con 'keystone':")
    keystone_methods = [m for m in methods if 'keystone' in m.lower()]
    for method in sorted(keystone_methods):
        print(f"    - {method}")
        
except ImportError as e:
    print(f"  ❌ Error con IamClient: {e}")

print("\n=== Fin de la exploración ===")
print("\nRecomendación: Actualiza iam_collector.py para usar solo las clases que existen.")
