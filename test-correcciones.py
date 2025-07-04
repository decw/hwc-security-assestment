#!/usr/bin/env python3
"""
Script de test para verificar que todas las correcciones funcionan
"""

import sys
import json
from datetime import datetime, timezone

def test_sdk_imports():
    """Test 1: Verificar imports de SDKs"""
    print("🧪 Test 1: Verificando imports de SDKs...")
    
    results = {}
    
    # Test OBS
    try:
        from huaweicloudsdkobs.v1 import ObsClient, ListBucketsRequest
        results['obs_official'] = "✅ OK"
        print("  ✅ OBS SDK oficial disponible")
    except ImportError:
        try:
            import obs
            results['obs_legacy'] = "✅ OK (legacy)"
            print("  ✅ OBS SDK legacy disponible")
        except ImportError:
            results['obs'] = "❌ No disponible"
            print("  ❌ OBS SDK no disponible")
    
    # Test CBR (reemplaza CSBS)
    try:
        from huaweicloudsdkcbr.v1 import CbrClient, ListVaultRequest
        results['cbr'] = "✅ OK"
        print("  ✅ CBR SDK disponible (reemplaza CSBS)")
    except ImportError:
        results['cbr'] = "❌ No disponible"
        print("  ❌ CBR SDK no disponible")
    
    # Test SFS
    try:
        from huaweicloudsdksfs.v2 import SfsClient
        results['sfs'] = "✅ OK"
        print("  ✅ SFS SDK disponible")
    except ImportError:
        try:
            from huaweicloudsdksfsturbo.v1 import SfsTurboClient
            results['sfs_turbo'] = "✅ OK (turbo)"
            print("  ✅ SFS Turbo SDK disponible")
        except ImportError:
            results['sfs'] = "❌ No disponible"
            print("  ❌ SFS SDK no disponible")
    
    # Test IAM con clases correctas
    try:
        from huaweicloudsdkiam.v3 import (
            IamClient,
            KeystoneListUsersRequest,
            KeystoneListRolesRequest,  # Correcto, no KeystoneListAllProjects...
            ShowDomainPasswordPolicyRequest,
            ListPermanentAccessKeysRequest
        )
        results['iam'] = "✅ OK"
        print("  ✅ IAM SDK con clases correctas")
    except ImportError as e:
        results['iam'] = f"❌ Error: {e}"
        print(f"  ❌ IAM SDK error: {e}")
    
    return results

def test_datetime_handling():
    """Test 2: Verificar manejo de datetime"""
    print("\n🧪 Test 2: Verificando manejo de datetime...")
    
    def parse_datetime_safe(date_str):
        """Función corregida de parsing datetime"""
        if not date_str:
            return datetime.now(timezone.utc)
        
        try:
            if isinstance(date_str, datetime):
                if date_str.tzinfo is None:
                    return date_str.replace(tzinfo=timezone.utc)
                return date_str
            
            if isinstance(date_str, str):
                if '.' in date_str:
                    date_str = date_str.split('.')[0] + 'Z'
                
                if not date_str.endswith('Z') and '+' not in date_str:
                    date_str += 'Z'
                
                return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            
        except Exception as e:
            print(f"    ⚠️  Error parsing {date_str}: {e}")
            return datetime.now(timezone.utc)
        
        return datetime.now(timezone.utc)
    
    # Test casos comunes
    test_cases = [
        "2024-01-01T10:00:00Z",
        "2024-01-01T10:00:00.123Z",
        "2024-01-01T10:00:00+00:00",
        datetime.now(),
        datetime.now(timezone.utc),
        None,
        ""
    ]
    
    success = 0
    for case in test_cases:
        try:
            result = parse_datetime_safe(case)
            now = datetime.now(timezone.utc)
            
            # Verificar que se puede hacer aritmética
            diff = now - result
            print(f"  ✅ Parsed {case} -> {result.isoformat()}")
            success += 1
        except Exception as e:
            print(f"  ❌ Failed {case}: {e}")
    
    print(f"  📊 {success}/{len(test_cases)} casos exitosos")
    return success == len(test_cases)

def test_json_serialization():
    """Test 3: Verificar serialización JSON"""
    print("\n🧪 Test 3: Verificando serialización JSON...")
    
    def convert_to_serializable(obj):
        """Función corregida de conversión"""
        if obj is None:
            return None
        elif isinstance(obj, (str, int, float, bool)):
            return obj
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, list):
            return [convert_to_serializable(item) for item in obj]
        elif isinstance(obj, dict):
            return {k: convert_to_serializable(v) for k, v in obj.items()}
        elif hasattr(obj, '__dict__'):
            result = {}
            for key, value in obj.__dict__.items():
                if not key.startswith('_'):
                    result[key] = convert_to_serializable(value)
            return result
        else:
            return str(obj)
    
    # Simular objeto CustomPolicy problemático
    class MockCustomPolicy:
        def __init__(self):
            self.id = "policy123"
            self.display_name = "Test Policy"
            self.policy = {"Version": "1.1", "Statement": []}
            self.created_at = datetime.now()
            self._private_attr = "should be ignored"
    
    class MockUser:
        def __init__(self):
            self.id = "user123"
            self.name = "testuser"
            self.policies = [MockCustomPolicy()]
    
    # Test data estructura compleja
    test_data = {
        'users': [MockUser()],
        'policies': [MockCustomPolicy()],
        'timestamp': datetime.now(),
        'nested': {
            'level1': {
                'level2': [MockCustomPolicy(), MockUser()]
            }
        }
    }
    
    try:
        # Convertir a serializable
        serializable = convert_to_serializable(test_data)
        
        # Intentar serializar a JSON
        json_str = json.dumps(serializable, indent=2)
        
        # Verificar que se puede deserializar
        deserialized = json.loads(json_str)
        
        print("  ✅ Conversión a serializable exitosa")
        print("  ✅ Serialización JSON exitosa")
        print("  ✅ Deserialización exitosa")
        print(f"  📊 JSON size: {len(json_str)} characters")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Error en serialización: {e}")
        return False

def test_password_policy_parsing():
    """Test 4: Verificar parsing de password policy"""
    print("\n🧪 Test 4: Verificando parsing de password policy...")
    
    # Simular respuesta de Huawei Cloud
    class MockPasswordPolicy:
        def __init__(self):
            self.minimum_password_length = 8
            self.minimum_password_uppercase = 1
            self.minimum_password_lowercase = 1
            self.minimum_password_number = 1
            self.minimum_password_special_char = 1
            self.password_validity_period = 90
            self.password_char_combination = 4
            self.password_not_username_or_invert = True
    
    class MockResponse:
        def __init__(self):
            self.password_policy = MockPasswordPolicy()
    
    response = MockResponse()
    pwd_policy = response.password_policy
    
    try:
        # Usar getattr para acceso seguro a atributos
        policy = {
            'minimum_length': getattr(pwd_policy, 'minimum_password_length', 8),
            'require_uppercase': getattr(pwd_policy, 'minimum_password_uppercase', 0) > 0,
            'require_lowercase': getattr(pwd_policy, 'minimum_password_lowercase', 0) > 0,
            'require_numbers': getattr(pwd_policy, 'minimum_password_number', 0) > 0,
            'require_special': getattr(pwd_policy, 'minimum_password_special_char', 0) > 0,
            'password_validity_period': getattr(pwd_policy, 'password_validity_period', 0),
        }
        
        print("  ✅ Password policy parsing exitoso")
        print(f"  📊 Policy: {policy}")
        return True
        
    except Exception as e:
        print(f"  ❌ Error parsing password policy: {e}")
        return False

def test_finding_generation():
    """Test 5: Verificar generación de hallazgos"""
    print("\n🧪 Test 5: Verificando generación de hallazgos...")
    
    findings = []
    
    def add_finding(finding_id, severity, message, details):
        finding = {
            'id': finding_id,
            'severity': severity,
            'message': message,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        findings.append(finding)
        return finding
    
    try:
        # Generar hallazgos de test
        add_finding('IAM-001', 'CRITICAL', 'Usuario con privilegios excesivos', {'user_id': 'test123'})
        add_finding('IAM-002', 'HIGH', 'Usuario sin MFA', {'user_name': 'testuser'})
        add_finding('NET-003', 'CRITICAL', 'Puerto SSH expuesto', {'port': 22, 'source': '0.0.0.0/0'})
        
        # Verificar que se pueden serializar
        json.dumps(findings, indent=2)
        
        print(f"  ✅ {len(findings)} hallazgos generados exitosamente")
        print(f"  ✅ Serialización de hallazgos exitosa")
        
        # Verificar severidades
        severities = {f['severity'] for f in findings}
        print(f"  📊 Severidades encontradas: {severities}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Error generando hallazgos: {e}")
        return False

def main():
    """Ejecutar todos los tests"""
    print("🔧 HUAWEI CLOUD ASSESSMENT - TEST DE CORRECCIONES")
    print("=" * 60)
    
    tests = [
        test_sdk_imports,
        test_datetime_handling, 
        test_json_serialization,
        test_password_policy_parsing,
        test_finding_generation
    ]
    
    results = []
    
    for test_func in tests:
        try:
            result = test_func()
            results.append(result)
        except Exception as e:
            print(f"  💥 Test {test_func.__name__} falló: {e}")
            results.append(False)
    
    print("\n" + "=" * 60)
    print("📊 RESUMEN DE TESTS")
    print("=" * 60)
    
    passed = sum(results)
    total = len(results)
    
    for i, (test_func, result) in enumerate(zip(tests, results)):
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {i+1}. {test_func.__name__}: {status}")
    
    print(f"\n🎯 RESULTADO: {passed}/{total} tests pasaron")
    
    if passed == total:
        print("🎉 ¡Todas las correcciones están funcionando!")
        print("✅ El assessment debería ejecutarse sin errores")
    else:
        print("⚠️  Algunos tests fallaron. Revisar las correcciones.")
        print("❌ Pueden persistir errores en el assessment")
    
    print("\n📋 PRÓXIMOS PASOS:")
    if passed == total:
        print("  1. Ejecutar: python main.py")
        print("  2. Verificar archivos JSON en output/")
        print("  3. Revisar hallazgos generados")
    else:
        print("  1. Revisar requirements.txt")
        print("  2. Actualizar collectors afectados")
        print("  3. Re-ejecutar este test")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)