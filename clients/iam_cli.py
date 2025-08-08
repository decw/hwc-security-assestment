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
    """Determinar el nombre del archivo de salida"""
    if args.output:
        return args.output
    
    if args.simple_output:
        return "iam_results.json"
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"iam_results_{timestamp}.json"

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
            report_generator = IAMReportGenerator(results)
            report_files = report_generator.generate_complete_report(output_path.parent)
            
            print("\n📊 Reportes detallados generados:")
            print(f"   Resumen detallado: {report_files['summary']}")
            print(f"  📊 CSV de hallazgos: {report_files['csv']}")
            print(f"  📋 Plan de remediación: {report_files['remediation']}")
            
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
        print(f"   MFA Habilitado: {mfa.get('mfa_enabled', 0)}/{mfa.get('total_users', 0)}")
    
    if 'findings' in results:
        print(f"  ⚠️  Hallazgos: {len(results['findings'])}")
    
    if analysis_results:
        print("\n RESUMEN DEL ANÁLISIS:")
        summary = analysis_results.get('summary', {})
        print(f"  🚨 Vulnerabilidades: {summary.get('total_vulnerabilities', 0)}")
        
        by_severity = summary.get('by_severity', {})
        for severity, count in by_severity.items():
            if count > 0:
                print(f"    {severity}: {count}")

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
            print(f"\n⚠️  Este proceso analizará los datos del archivo: {args.input}")
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
        
        # Guardar resultados
        output_file = get_output_filename(args)
        if not save_results(results, output_file):
            sys.exit(1)
        
        # Guardar análisis por separado si existe
        if analysis_results:
            analysis_file = output_file.replace('.json', '_analysis.json')
            if not save_results(analysis_results, analysis_file):
                print("⚠️  No se pudo guardar el análisis por separado")
        
        # Mostrar resumen
        print_summary(results, analysis_results)
    
    print("\n✅ Operación completada exitosamente!")

if __name__ == "__main__":
    asyncio.run(main())
