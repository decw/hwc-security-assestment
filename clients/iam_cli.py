#!/usr/bin/env python3
"""
CLI unificado para el colector IAM de Huawei Cloud
Importa: collectors.iam_collector y analyzers.vulnerability_analizer_modules_iam_network

Uso:
  python3 -m clients.iam_cli                    # Recolección completa
  python3 -m clients.iam_cli --help            # Ver opciones
  python3 -m clients.iam_cli --check-mfa-only  # Solo MFA
  python3 -m clients.iam_cli --analyze-only    # Solo análisis
"""

import asyncio
import json
import sys
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict

# Agregar el directorio raíz al path para importaciones
sys.path.append(str(Path(__file__).parent.parent))


def print_banner():
    """Imprimir banner del script"""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║              HUAWEI CLOUD IAM COLLECTOR CLI              ║
    ╠═══════════════════════════════════════════════════════════╣
    ║  Recolección y análisis de datos IAM                     ║
    ║  Powered by: Security Team                               ║
    ╚═══════════════════════════════════════════════════════════╝
    """)


def setup_argument_parser():
    """Configurar parser de argumentos de línea de comandos"""
    parser = argparse.ArgumentParser(
        description='CLI unificado para IAM - Recolección y Análisis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python3 -m clients.iam_cli                           # Recolección completa + análisis
  python3 -m clients.iam_cli --collect-only           # Solo recolección
  python3 -m clients.iam_cli --analyze-only           # Solo análisis (requiere datos)
  python3 -m clients.iam_cli --check-mfa-only         # Solo verificar MFA
  python3 -m clients.iam_cli --output mi_reporte.json # Archivo personalizado
  python3 -m clients.iam_cli --verbose --no-confirm   # Modo detallado sin confirmación
        """
    )

    # Modos de operación
    parser.add_argument(
        '--collect-only',
        action='store_true',
        help='Solo realizar recolección de datos (sin análisis)'
    )

    parser.add_argument(
        '--analyze-only',
        action='store_true',
        help='Solo realizar análisis (requiere archivo de datos con --input)'
    )

    parser.add_argument(
        '--input', '-i',
        type=str,
        help='Archivo de entrada para análisis (requerido con --analyze-only)'
    )

    # Opciones de recolección específicas
    parser.add_argument(
        '--check-mfa-only',
        action='store_true',
        help='Solo verificar estado de MFA de usuarios'
    )

    parser.add_argument(
        '--check-users-only',
        action='store_true',
        help='Solo recolectar información de usuarios'
    )

    parser.add_argument(
        '--check-policies-only',
        action='store_true',
        help='Solo recolectar políticas y roles'
    )

    parser.add_argument(
        '--check-access-keys-only',
        action='store_true',
        help='Solo verificar access keys'
    )

    # Opciones de salida
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Archivo de salida (default: iam_results_YYYYMMDD_HHMMSS.json)'
    )

    parser.add_argument(
        '--simple-output',
        action='store_true',
        help='Usar nombre de archivo simple (iam_results.json)'
    )

    # Opciones de comportamiento
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Modo verbose con logs detallados'
    )

    parser.add_argument(
        '--no-confirm',
        action='store_true',
        help='Ejecutar sin confirmación del usuario'
    )

    return parser


def verify_credentials():
    """Verificar que las credenciales estén configuradas"""
    try:
        from config.settings import HUAWEI_ACCESS_KEY, HUAWEI_SECRET_KEY, HUAWEI_DOMAIN_ID
        if not all([HUAWEI_ACCESS_KEY, HUAWEI_SECRET_KEY, HUAWEI_DOMAIN_ID]):
            print("❌ ERROR: Credenciales de Huawei Cloud no configuradas")
            print("Por favor configure las siguientes variables de entorno:")
            print("  - HUAWEI_ACCESS_KEY")
            print("  - HUAWEI_SECRET_KEY")
            print("  - HUAWEI_DOMAIN_ID")
            return False
        return True
    except ImportError as e:
        print(f"❌ ERROR: No se pudo importar config.settings: {e}")
        return False


def get_output_filename(args):
    """Determinar la ruta/nombre del archivo de salida dentro de reports/iam/"""
    # Importar aquí porque a esta altura ya agregamos el directorio raíz al sys.path
    from config.settings import REPORTS_DIR

    base_dir = Path(REPORTS_DIR) / 'iam'         # Aseguramos Path y subdir
    base_dir.mkdir(parents=True, exist_ok=True)

    # 1. Si el usuario indicó --output se respeta el nombre, pero se fuerza la ruta
    if args.output:
        file_name = Path(args.output).name  # evitamos rutas externas
    elif args.simple_output:
        file_name = "iam_results.json"
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"iam_results_{timestamp}.json"

    return str(base_dir / file_name)


async def run_collection(args):
    """Ejecutar la recolección según las opciones especificadas"""
    try:
        # Importar el colector
        from collectors.iam_collector import IAMCollector
        collector = IAMCollector()

        print("✅ Colector IAM inicializado correctamente")

        # Determinar qué recolectar según las opciones
        if args.check_mfa_only:
            print("📋 Modo: Solo verificación de MFA")
            users = await collector._collect_users()
            mfa_status = await collector._collect_mfa_status(users)
            results = {
                'mfa_status': mfa_status,
                'timestamp': datetime.now().isoformat()
            }

        elif args.check_users_only:
            print("📋 Modo: Solo información de usuarios")
            users = await collector._collect_users()
            mfa_status = await collector._collect_mfa_status(users)
            results = {
                'users': users,
                'mfa_status': mfa_status,
                'timestamp': datetime.now().isoformat()
            }

        elif args.check_policies_only:
            print("📋 Modo: Solo políticas y roles")
            groups = await collector._collect_groups()
            roles = await collector._collect_roles()
            policies = await collector._collect_policies()
            results = {
                'groups': groups,
                'roles': roles,
                'policies': policies,
                'timestamp': datetime.now().isoformat()
            }

        elif args.check_access_keys_only:
            print("📋 Modo: Solo access keys")
            users = await collector._collect_users()
            access_keys = await collector._collect_access_keys(users)
            results = {
                'access_keys': access_keys,
                'timestamp': datetime.now().isoformat()
            }

        else:
            print("📋 Modo: Recolección completa")
            results = await collector.collect_all()

        return results, None

    except ImportError as e:
        return None, f"❌ ERROR: No se pudo importar IAMCollector: {e}"
    except Exception as e:
        return None, f"❌ ERROR durante la recolección: {e}"


async def run_analysis(iam_data, args):
    """Ejecutar análisis de vulnerabilidades"""
    try:
        # Importar el analizador
        from analyzers.vulnerability_analizer_modules_iam_network import IAMNetworkVulnerabilityAnalyzer
        analyzer = IAMNetworkVulnerabilityAnalyzer()

        print("✅ Analizador IAM inicializado correctamente")

        # Ejecutar análisis
        print("🔍 Analizando vulnerabilidades IAM...")
        analyzer.analyze_iam_vulnerabilities(iam_data)

        # Obtener resultados
        vulnerabilities = analyzer.get_vulnerabilities()

        analysis_results = {
            'vulnerabilities': [vuln.to_dict() for vuln in vulnerabilities],
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'by_severity': analyzer.get_vulnerabilities_by_severity(),
                'by_type': analyzer.get_vulnerabilities_by_type()
            },
            'timestamp': datetime.now().isoformat()
        }

        return analysis_results, None

    except ImportError as e:
        return None, f"❌ ERROR: No se pudo importar IAMNetworkVulnerabilityAnalyzer: {e}"
    except Exception as e:
        return None, f"❌ ERROR durante el análisis: {e}"


def save_results(results, output_file):
    """Guardar resultados en archivo JSON y generar reportes detallados"""
    try:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Guardar JSON
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)

        print(f"💾 Resultados JSON guardados en: {output_path}")

        # Generar reportes detallados
        try:
            from utils.iam_report_generator import IAMReportGenerator
            # CAMBIAR: results -> collection_data (datos de recolección)
            report_generator = IAMReportGenerator(results)
            report_files = report_generator.generate_complete_report(
                output_path.parent)

            print("\n📊 Reportes detallados generados:")
            print(f"   📊 Resumen detallado: {report_files['summary']}")
            print(f"   📊 CSV de hallazgos: {report_files['csv']}")
            print(f"   📋 Plan de remediación: {report_files['remediation']}")

        except ImportError as e:
            print(f"⚠️ No se pudo generar reporte detallado: {e}")
        except Exception as e:
            print(f"⚠️ Error generando reportes: {e}")

        return True
    except Exception as e:
        print(f"❌ ERROR guardando resultados: {e}")
        return False


def load_data(input_file):
    """Cargar datos desde archivo JSON"""
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ ERROR cargando datos: {e}")
        return None


def print_summary(results, analysis_results=None):
    """Imprimir resumen de los resultados"""
    print("\n📊 RESUMEN DE LA RECOLECCIÓN:")

    if 'users' in results:
        print(f"  👥 Usuarios: {len(results['users'])}")
    if 'groups' in results:
        print(f"  👥 Grupos: {len(results['groups'])}")
    if 'roles' in results:
        print(f"  🔑 Roles: {len(results['roles'])}")
    if 'policies' in results:
        print(f"  📜 Políticas: {len(results['policies'])}")
    if 'access_keys' in results:
        print(f"  🔑 Access Keys: {len(results['access_keys'])}")

    if 'mfa_status' in results:
        mfa = results['mfa_status']
        ver_methods = mfa.get('verification_methods', {})
        am_counts = mfa.get('access_mode_counts', {})

        total_console = am_counts.get('console', 0)
        total_service = am_counts.get('programmatic', 0)
        total_default = am_counts.get('default', 0)

        # ────── Resumen MFA en consola ───────────────────────────────────
        print("   ─── MFA ─────────────────────────────────────────────")
        print(f"   verification_methods: {ver_methods}")
        print(f"   total_console_users: {total_console}")
        print(f"   total_service_users: {total_service}")
        print(
            f"   total_default_users (programmatic + console): {total_default}")
        print(f"   mfa_enabled:         {mfa.get('mfa_enabled', 0)}")
        print(f"   mfa_disabled:        {mfa.get('mfa_disabled', 0)}")

        # mensaje resumido anterior (se mantiene)
        print(
            f"   MFA Habilitado: {mfa.get('mfa_enabled', 0)}/{total_console+total_default+total_service}")

    if 'findings' in results:
        print(f"  ⚠️  Hallazgos: {len(results['findings'])}")

    if analysis_results:
        print("\n RESUMEN DEL ANÁLISIS:")
        summary = analysis_results.get('summary', {})
        print(
            f"  🚨 Vulnerabilidades: {summary.get('total_vulnerabilities', 0)}")

        by_severity = summary.get('by_severity', {})
        for severity, count in by_severity.items():
            if count > 0:
                print(f"    {severity}: {count}")


def merge_collection_and_analysis(collection_data: Dict, analysis_data: Dict) -> Dict:
    """Combinar datos de recolección y análisis para reporte completo"""
    # Crear copia profunda de los datos de recolección
    import copy
    combined = copy.deepcopy(collection_data)

    # Asegurar que existan todos los campos necesarios para el reporte
    if 'statistics' not in combined:
        combined['statistics'] = {}

    # Corregir el campo de usuarios sin MFA
    if 'mfa_status' in combined:
        mfa_status = combined['mfa_status']
        # Unificar los campos de MFA
        if 'regular_users_without_mfa' in mfa_status:
            mfa_status['users_without_mfa'] = mfa_status.get(
                'regular_users_without_mfa', [])

        # Actualizar estadísticas con datos de MFA
        combined['statistics']['users_without_mfa'] = len(
            mfa_status.get('users_without_mfa', []))
        combined['statistics']['total_users'] = mfa_status.get(
            'total_users', 0)

        # Calcular tasa de cumplimiento MFA
        if combined['statistics']['total_users'] > 0:
            mfa_compliant = combined['statistics']['total_users'] - \
                combined['statistics']['users_without_mfa']
            combined['statistics']['mfa_compliance_rate'] = (
                mfa_compliant / combined['statistics']['total_users']) * 100
        else:
            combined['statistics']['mfa_compliance_rate'] = 0

    # Asegurar que existan los campos básicos
    essential_fields = ['users', 'groups', 'roles', 'policies', 'access_keys',
                        'privileged_accounts', 'inactive_users', 'service_accounts']
    for field in essential_fields:
        if field not in combined:
            combined[field] = []

    # Actualizar estadísticas con conteos reales
    combined['statistics'].update({
        'total_users': len(combined.get('users', [])),
        'total_groups': len(combined.get('groups', [])),
        'total_roles': len(combined.get('roles', [])),
        'total_policies': len(combined.get('policies', [])),
        'total_access_keys': len(combined.get('access_keys', [])),
        'inactive_users': len(combined.get('inactive_users', [])),
        'service_accounts': len(combined.get('service_accounts', [])),
        'privileged_accounts': len(combined.get('privileged_accounts', []))
    })

    # Calcular access keys antiguas (más de 90 días)
    old_keys_count = 0
    if 'access_keys' in combined:
        from datetime import datetime, timedelta
        ninety_days_ago = datetime.now() - timedelta(days=90)
        for key in combined['access_keys']:
            if 'created_date' in key:
                try:
                    # Parsear fecha según el formato que use Huawei Cloud
                    key_date = datetime.fromisoformat(
                        key['created_date'].replace('Z', '+00:00'))
                    if key_date < ninety_days_ago:
                        old_keys_count += 1
                except:
                    pass
    combined['statistics']['old_access_keys'] = old_keys_count

    # Procesar findings correctamente
    findings_by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

    # Contar findings del collector
    if 'findings' in combined:
        for finding in combined['findings']:
            severity = finding.get('severity', 'LOW').upper()
            if severity in findings_by_severity:
                findings_by_severity[severity] += 1

    # Agregar vulnerabilidades del análisis
    if analysis_data:
        combined['vulnerabilities'] = analysis_data.get('vulnerabilities', [])
        combined['vulnerability_summary'] = analysis_data.get('summary', {})

        # Contar vulnerabilidades del analyzer
        for vuln in combined.get('vulnerabilities', []):
            severity = vuln.get('severity', 'LOW').upper()
            if severity in findings_by_severity:
                findings_by_severity[severity] += 1

        # Combinar findings y vulnerabilities en un solo campo para el reporte
        all_findings = combined.get('findings', []).copy()

        # Convertir vulnerabilidades al formato de findings
        for vuln in combined.get('vulnerabilities', []):
            all_findings.append({
                'id': vuln.get('id', ''),
                'severity': vuln.get('severity', 'LOW'),
                'message': vuln.get('title', ''),
                'details': vuln.get('description', ''),
                'timestamp': vuln.get('discovered_date', '')
            })

        combined['findings'] = all_findings

    # Actualizar estadísticas de findings
    combined['statistics']['findings_by_severity'] = findings_by_severity

    # Calcular top risks basado en findings críticos y altos
    top_risks = []
    for finding in combined.get('findings', []):
        if finding.get('severity', '').upper() in ['CRITICAL', 'HIGH']:
            top_risks.append({
                'risk': finding.get('message', 'Sin descripción'),
                'severity': finding.get('severity', 'HIGH')
            })
    combined['statistics']['top_risks'] = top_risks[:5]  # Top 5 riesgos

    # Asegurar que password_policy y login_policy existan
    if 'password_policy' not in combined:
        combined['password_policy'] = {}
    if 'login_policy' not in combined:
        combined['login_policy'] = {}

    # Log para debugging
    print(f"📊 Datos combinados - Estadísticas finales:")
    print(
        f"   - Total usuarios: {combined['statistics'].get('total_users', 0)}")
    print(
        f"   - Usuarios sin MFA: {combined['statistics'].get('users_without_mfa', 0)}")
    print(
        f"   - Findings por severidad: {combined['statistics'].get('findings_by_severity', {})}")

    return combined


def validate_and_fix_report_data(data: Dict) -> Dict:
    """
    Validar y corregir la estructura de datos antes de generar el reporte.
    Asegura que todos los campos necesarios existan con valores por defecto apropiados.
    """
    import copy
    from datetime import datetime

    # Crear copia profunda para no modificar el original
    validated_data = copy.deepcopy(data)

    # 1. Asegurar campos principales
    required_fields = {
        'users': [],
        'groups': [],
        'roles': [],
        'policies': [],
        'access_keys': [],
        'findings': [],
        'privileged_accounts': [],
        'inactive_users': [],
        'service_accounts': [],
        'user_group_mappings': {},
        'role_assignments': {},
        'statistics': {},
        'password_policy': {},
        'login_policy': {},
        'protection_policy': {},
        'timestamp': datetime.now().isoformat()
    }

    for field, default_value in required_fields.items():
        if field not in validated_data:
            print(
                f"⚠️  Campo faltante '{field}' - agregando valor por defecto")
            validated_data[field] = default_value

    # 2. Validar y corregir mfa_status
    if 'mfa_status' not in validated_data:
        validated_data['mfa_status'] = {
            'total_users': 0,
            'mfa_enabled': 0,
            'mfa_disabled': 0,
            'users_without_mfa': []
        }
    else:
        mfa = validated_data['mfa_status']
        # Unificar campos de MFA
        if 'regular_users_without_mfa' in mfa and 'users_without_mfa' not in mfa:
            mfa['users_without_mfa'] = mfa['regular_users_without_mfa']

        # Asegurar campos básicos
        mfa.setdefault('total_users', len(validated_data.get('users', [])))
        mfa.setdefault('mfa_enabled', 0)
        mfa.setdefault('mfa_disabled', mfa.get(
            'total_users', 0) - mfa.get('mfa_enabled', 0))
        mfa.setdefault('users_without_mfa', [])

    # 3. Calcular estadísticas completas
    stats = validated_data['statistics']

    # Conteos básicos
    stats['total_users'] = len(validated_data.get('users', []))
    stats['total_groups'] = len(validated_data.get('groups', []))
    stats['total_roles'] = len(validated_data.get('roles', []))
    stats['total_policies'] = len(validated_data.get('policies', []))
    stats['total_access_keys'] = len(validated_data.get('access_keys', []))

    # Usuarios especiales
    stats['inactive_users'] = len(validated_data.get('inactive_users', []))
    stats['service_accounts'] = len(validated_data.get('service_accounts', []))
    stats['privileged_accounts'] = len(
        validated_data.get('privileged_accounts', []))

    # MFA stats
    mfa_data = validated_data.get('mfa_status', {})
    stats['users_without_mfa'] = len(mfa_data.get('users_without_mfa', []))

    # Calcular tasa de cumplimiento MFA
    if stats['total_users'] > 0:
        mfa_compliant = stats['total_users'] - stats['users_without_mfa']
        stats['mfa_compliance_rate'] = (
            mfa_compliant / stats['total_users']) * 100
    else:
        stats['mfa_compliance_rate'] = 0.0

    # Access keys analysis
    stats['old_access_keys'] = 0
    stats['unused_access_keys'] = 0

    if 'access_keys' in validated_data:
        from datetime import datetime, timedelta
        ninety_days_ago = datetime.now() - timedelta(days=90)

        for key in validated_data['access_keys']:
            # Verificar keys antiguas
            if 'created_date' in key:
                try:
                    key_date_str = key['created_date']
                    # Manejar diferentes formatos de fecha
                    if 'T' in key_date_str:
                        key_date = datetime.fromisoformat(
                            key_date_str.replace('Z', '+00:00'))
                    else:
                        key_date = datetime.strptime(key_date_str, '%Y-%m-%d')

                    if key_date < ninety_days_ago:
                        stats['old_access_keys'] += 1
                except Exception as e:
                    print(f"⚠️  Error parseando fecha de access key: {e}")

            # Verificar keys sin uso
            if not key.get('last_used_date'):
                stats['unused_access_keys'] += 1

    # 4. Procesar findings y calcular por severidad
    findings_by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

    # Procesar findings existentes
    for finding in validated_data.get('findings', []):
        severity = finding.get('severity', 'LOW').upper()
        if severity in findings_by_severity:
            findings_by_severity[severity] += 1

    # Procesar vulnerabilidades si existen
    for vuln in validated_data.get('vulnerabilities', []):
        severity = vuln.get('severity', 'LOW').upper()
        if severity in findings_by_severity:
            findings_by_severity[severity] += 1

    stats['findings_by_severity'] = findings_by_severity

    # 5. Identificar top risks
    top_risks = []
    all_issues = validated_data.get(
        'findings', []) + validated_data.get('vulnerabilities', [])

    for issue in all_issues:
        if issue.get('severity', '').upper() in ['CRITICAL', 'HIGH']:
            risk_entry = {
                'risk': issue.get('message', issue.get('title', 'Sin descripción')),
                'severity': issue.get('severity', 'HIGH'),
                'id': issue.get('id', 'N/A')
            }
            if risk_entry not in top_risks:
                top_risks.append(risk_entry)

    # Ordenar por severidad (CRITICAL primero)
    top_risks.sort(
        key=lambda x: 0 if x['severity'].upper() == 'CRITICAL' else 1)
    stats['top_risks'] = top_risks[:10]  # Top 10 riesgos

    # 6. Log de validación
    print("\n✅ Validación de datos completada:")
    print(f"   - Usuarios: {stats['total_users']}")
    print(f"   - Grupos: {stats['total_groups']}")
    print(f"   - Roles: {stats['total_roles']}")
    print(f"   - Políticas: {stats['total_policies']}")
    print(f"   - Access Keys: {stats['total_access_keys']}")
    print(f"   - Usuarios sin MFA: {stats['users_without_mfa']}")
    print(f"   - Hallazgos totales: {sum(findings_by_severity.values())}")
    print(f"     • Críticos: {findings_by_severity['CRITICAL']}")
    print(f"     • Altos: {findings_by_severity['HIGH']}")
    print(f"     • Medios: {findings_by_severity['MEDIUM']}")
    print(f"     • Bajos: {findings_by_severity['LOW']}")

    return validated_data


def generate_comprehensive_report(combined_data: Dict, base_output_file: str):
    """Generar reporte completo con datos de recolección y análisis"""
    try:
        from utils.iam_report_generator import IAMReportGenerator
        from pathlib import Path

        # Validar y corregir datos antes de generar el reporte
        validated_data = validate_and_fix_report_data(combined_data)
        # Usar datos combinados para el reporte
        report_generator = IAMReportGenerator(validated_data)
        output_path = Path(base_output_file)
        report_files = report_generator.generate_complete_report(
            output_path.parent)

        print("\n📊 Reporte completo generado (Recolección + Análisis):")
        print(f"   📋 Resumen detallado: {report_files['summary']}")
        print(f"   📊 CSV de hallazgos: {report_files['csv']}")
        print(f"   📋 Plan de remediación: {report_files['remediation']}")

    except Exception as e:
        print(f"⚠️ Error generando reporte completo: {e}")


async def main():
    """Función principal"""
    # Configurar parser de argumentos
    parser = setup_argument_parser()
    args = parser.parse_args()

    # Mostrar banner
    print_banner()

    # Verificar argumentos incompatibles
    if args.analyze_only and not args.input:
        print("❌ ERROR: --analyze-only requiere --input para especificar archivo de datos")
        sys.exit(1)

    # Verificar credenciales (solo si no es solo análisis)
    if not args.analyze_only and not verify_credentials():
        sys.exit(1)

    # Mostrar configuración
    if args.verbose:
        print(f"🔧 Configuración:")
        if not args.analyze_only:
            print(f"  Archivo de salida: {get_output_filename(args)}")
        if args.analyze_only:
            print(f"  Archivo de entrada: {args.input}")
        print(f"  Modo verbose: {'Sí' if args.verbose else 'No'}")

    # Confirmar ejecución
    if not args.no_confirm:
        if args.analyze_only:
            print(
                f"\n⚠️  Este proceso analizará los datos del archivo: {args.input}")
        else:
            print("\n⚠️  Este proceso recolectará datos IAM de Huawei Cloud.")
        response = input("¿Desea continuar? (s/n): ")
        if response.lower() != 's':
            print("Operación cancelada.")
            return

    # Ejecutar según el modo
    if args.analyze_only:
        # Modo solo análisis
        print(f"\n🔄 Cargando datos desde: {args.input}")
        iam_data = load_data(args.input)
        if not iam_data:
            sys.exit(1)

        analysis_results, error = await run_analysis(iam_data, args)
        if error:
            print(error)
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)

        # Guardar resultados del análisis
        output_file = get_output_filename(args) or "iam_analysis_results.json"
        if not save_results(analysis_results, output_file):
            sys.exit(1)

        print_summary(iam_data, analysis_results)

    else:
        # Modo recolección (con o sin análisis)
        print("\n🔄 Iniciando recolección de datos IAM...")
        results, error = await run_collection(args)

        if error:
            print(error)
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)

        print("✅ Recolección completada exitosamente")

        # Ejecutar análisis si no es solo recolección
        analysis_results = None
        if not args.collect_only:
            print("\n Iniciando análisis de vulnerabilidades...")
            analysis_results, error = await run_analysis(results, args)

            if error:
                print(f"⚠️  ADVERTENCIA: {error}")
                print("Continuando solo con los datos recolectados...")
            else:
                print("✅ Análisis completado exitosamente")

        # Guardar resultados de recolección
        output_file = get_output_filename(args)
        if not save_results(results, output_file):
            sys.exit(1)

        # Ejecutar análisis y combinar resultados para el reporte
        if analysis_results:
            # NUEVO: Combinar datos para el reporte completo
            combined_results = merge_collection_and_analysis(
                results, analysis_results)

            # Generar reporte completo con datos combinados
            generate_comprehensive_report(combined_results, output_file)

            # Guardar análisis por separado
            analysis_file = output_file.replace('.json', '_analysis.json')
            if not save_results(analysis_results, analysis_file):
                print("⚠️  No se pudo guardar el análisis por separado")

        # Mostrar resumen
        print_summary(results, analysis_results)

    print("\n✅ Operación completada exitosamente!")

if __name__ == "__main__":
    asyncio.run(main())
