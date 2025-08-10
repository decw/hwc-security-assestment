#!/usr/bin/env python3
"""
Ejemplo de uso de los analizadores modulares de vulnerabilidades
Muestra cómo importar y usar los nuevos módulos separados
"""

from analyzers import IAMNetworkVulnerabilityAnalyzer  # Alias de compatibilidad
from analyzers.vulnerability_analyzer_modules import ModuleVulnerabilityAnalyzer
from analyzers.vulnerability_analyzer_network import NetworkVulnerabilityAnalyzer
from analyzers.vulnerability_analyzer_iam import IAMVulnerabilityAnalyzer
import json
import sys
from pathlib import Path

# Agregar el directorio padre al path para importaciones
sys.path.append(str(Path(__file__).parent.parent))

# ==============================================================================
# OPCIÓN 1: Importar analyzers específicos individualmente
# ==============================================================================


def example_individual_analyzers():
    """Ejemplo usando analyzers individuales"""
    print("=== Usando Analyzers Individuales ===\n")

    # Datos de ejemplo para IAM
    iam_data = {
        'users': [
            {
                'user_name': 'admin-user',
                'create_date': '2024-01-01T00:00:00Z',
                'access_keys': [
                    {
                        'access_key_id': 'AKID****1234',
                        'status': 'Active',
                        'create_date': '2023-01-01T00:00:00Z'  # Key antigua
                    }
                ],
                'groups': [],
                'attached_policies': [
                    {'name': 'AdministratorAccess'}
                ]
            }
        ],
        'mfa_analysis': {
            'users_without_mfa': [
                {
                    'user_name': 'admin-user',
                    'has_login_profile': True
                }
            ]
        },
        'permissions_analysis': {
            'users_with_admin_access': [
                {
                    'user_name': 'admin-user',
                    'source': 'AdministratorAccess policy'
                }
            ]
        }
    }

    # Analizar IAM
    iam_analyzer = IAMVulnerabilityAnalyzer()
    iam_vulnerabilities = iam_analyzer.analyze(iam_data)

    print(f"Vulnerabilidades IAM encontradas: {len(iam_vulnerabilities)}")
    for vuln in iam_vulnerabilities:
        print(f"  - [{vuln.code}] {vuln.title} (Severidad: {vuln.severity})")

    # Datos de ejemplo para Network
    network_data = {
        'vpcs': [
            {
                'id': 'vpc-001',
                'name': 'production-vpc',
                'subnets': [
                    {
                        'id': 'subnet-001',
                        'name': 'public-subnet',
                        'is_public': True,
                        'cidr_block': '10.0.1.0/24',
                        'instances': []
                    }
                ]
            }
        ],
        'security_groups': [
            {
                'id': 'sg-001',
                'name': 'web-sg',
                'ingress_rules': [
                    {
                        'source': '0.0.0.0/0',
                        'from_port': 22,
                        'to_port': 22,
                        'protocol': 'tcp'
                    }
                ]
            }
        ]
    }

    # Analizar Network
    network_analyzer = NetworkVulnerabilityAnalyzer()
    network_vulnerabilities = network_analyzer.analyze(network_data)

    print(
        f"\nVulnerabilidades de Red encontradas: {len(network_vulnerabilities)}")
    for vuln in network_vulnerabilities:
        print(f"  - [{vuln.code}] {vuln.title} (Severidad: {vuln.severity})")


# ==============================================================================
# OPCIÓN 2: Usar el coordinador de módulos (recomendado)
# ==============================================================================


def example_module_coordinator():
    """Ejemplo usando el coordinador de módulos"""
    print("\n=== Usando Coordinador de Módulos ===\n")

    # Crear instancia del coordinador
    analyzer = ModuleVulnerabilityAnalyzer()

    # Datos de assessment completos
    assessment_data = {
        'iam': {
            'users': [
                {
                    'user_name': 'test-user',
                    'create_date': '2024-01-01T00:00:00Z',
                    'password_last_used': '2023-01-01T00:00:00Z'  # Usuario inactivo
                }
            ],
            'groups': [
                {
                    'name': 'empty-group',
                    'attached_policies': []  # Grupo sin políticas
                }
            ],
            'policies': [],
            'mfa_analysis': {
                'users_without_mfa': []
            }
        },
        'network': {
            'vpcs': [
                {
                    'id': 'vpc-002',
                    'name': 'test-vpc',
                    'subnets': [],
                    'flow_logs_enabled': False  # Sin flow logs
                }
            ],
            'security_groups': [],
            'load_balancers': [
                {
                    'id': 'elb-001',
                    'name': 'public-elb',
                    'listeners': [
                        {
                            'protocol': 'HTTP',  # Sin cifrado
                            'port': 80
                        }
                    ]
                }
            ]
        }
    }

    # Analizar IAM
    iam_vulns = analyzer.analyze_iam_vulnerabilities(assessment_data['iam'])
    print(f"Vulnerabilidades IAM: {len(iam_vulns)}")

    # Analizar Network
    network_vulns = analyzer.analyze_network_vulnerabilities(
        assessment_data['network'])
    print(f"Vulnerabilidades Network: {len(network_vulns)}")

    # Obtener resumen consolidado
    summary = analyzer.get_consolidated_summary()
    print(f"\n=== Resumen Consolidado ===")
    print(f"Total de vulnerabilidades: {summary['total_vulnerabilities']}")
    print(f"Por módulo: {summary['by_module']}")
    print(f"Por severidad: {summary['by_severity']}")

    # Exportar reporte modular
    report = analyzer.export_modular_report()
    print(f"\nReporte generado con {len(report['modules'])} módulos")


# ==============================================================================
# OPCIÓN 3: Compatibilidad con código existente
# ==============================================================================


def example_backward_compatibility():
    """Ejemplo mostrando compatibilidad con código existente"""
    print("\n=== Compatibilidad con Código Existente ===\n")

    # El código antiguo que usaba IAMNetworkVulnerabilityAnalyzer
    # seguirá funcionando sin cambios
    analyzer = IAMNetworkVulnerabilityAnalyzer()

    data = {
        'iam': {'users': [], 'groups': [], 'policies': []},
        'network': {'vpcs': [], 'security_groups': []}
    }

    # Los métodos antiguos siguen funcionando
    analyzer.analyze_iam_vulnerabilities(data['iam'])
    analyzer.analyze_network_vulnerabilities(data['network'])

    print("✓ Código existente funciona sin modificaciones")

# ==============================================================================
# OPCIÓN 4: Importación desde otros archivos (ejemplo para main.py)
# ==============================================================================


def example_imports_for_main():
    """Ejemplo de cómo importar en main.py u otros archivos"""

    # En main.py o collectors/iam_collector.py:
    # from analyzers import IAMVulnerabilityAnalyzer

    # En main.py para análisis completo:
    # from analyzers import ModuleVulnerabilityAnalyzer

    # Para mantener compatibilidad:
    # from analyzers import IAMNetworkVulnerabilityAnalyzer

    print("\n=== Ejemplos de Importación ===")
    print("# En main.py:")
    print("from analyzers import ModuleVulnerabilityAnalyzer")
    print("")
    print("# En collectors/iam_collector.py:")
    print("from analyzers import IAMVulnerabilityAnalyzer")
    print("")
    print("# En clients/iam_cli.py (compatibilidad):")
    print("from analyzers import IAMNetworkVulnerabilityAnalyzer")

# ==============================================================================
# OPCIÓN 5: Uso con el archivo de referencias CSV
# ==============================================================================


def example_with_csv_references():
    """Ejemplo mostrando el mapeo con security_references.csv"""
    print("\n=== Uso con Referencias CSV ===\n")

    analyzer = IAMVulnerabilityAnalyzer()

    # Los códigos ahora hacen match con el CSV
    test_data = {
        'users': [],
        'account_settings': {},  # Sin política de contraseñas
        'mfa_analysis': {'users_without_mfa': []}
    }

    # Esto generará vulnerabilidad IAM-004 que existe en el CSV
    vulnerabilities = analyzer.analyze(test_data)

    for vuln in vulnerabilities:
        print(f"Código: {vuln.code}")
        print(f"  - Título (del CSV): {vuln.title}")
        print(f"  - Severidad (del CSV): {vuln.severity}")
        print(f"  - CVSS Score (del CSV): {vuln.cvss_score}")
        print(f"  - Frameworks: {vuln.frameworks}")
        print(
            f"  - Tiempo remediación: {vuln.remediation.get('time_days')} días")

# ==============================================================================
# MAIN - Ejecutar ejemplos
# ==============================================================================


def main():
    """Función principal para ejecutar todos los ejemplos"""

    print("="*70)
    print("EJEMPLOS DE USO DE ANALYZERS MODULARES")
    print("="*70)

    # Ejecutar ejemplos
    example_individual_analyzers()
    example_module_coordinator()
    example_backward_compatibility()
    example_imports_for_main()
    example_with_csv_references()

    print("\n" + "="*70)
    print("✓ Todos los ejemplos ejecutados exitosamente")
    print("="*70)


if __name__ == "__main__":
    main()
