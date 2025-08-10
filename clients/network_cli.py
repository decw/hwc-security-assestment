#!/usr/bin/env python3
"""
CLI unificado para el colector Network de Huawei Cloud
Importa: collectors.network_collector y analyzers.vulnerability_analyzer_network

Uso:
  python3 -m clients.network_cli                    # Recolección completa
  python3 -m clients.network_cli --help            # Ver opciones
  python3 -m clients.network_cli --check-sgs-only  # Solo Security Groups
  python3 -m clients.network_cli --analyze-only    # Solo análisis
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
    ║           HUAWEI CLOUD NETWORK COLLECTOR CLI             ║
    ╠═══════════════════════════════════════════════════════════╣
    ║  Recolección y análisis de datos de Red                  ║
    ║  Powered by: Security Team                               ║
    ╚═══════════════════════════════════════════════════════════╝
    """)


def setup_argument_parser():
    """Configurar parser de argumentos de línea de comandos"""
    parser = argparse.ArgumentParser(
        description='CLI unificado para Network - Recolección y Análisis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python3 -m clients.network_cli                      # Recolección completa + análisis
  python3 -m clients.network_cli --collect-only       # Solo recolección
  python3 -m clients.network_cli --analyze-only       # Solo análisis
  python3 -m clients.network_cli --check-sgs-only     # Solo Security Groups
  python3 -m clients.network_cli --check-exposed-only # Solo recursos expuestos
  python3 -m clients.network_cli --verbose            # Modo verbose
  python3 -m clients.network_cli --output custom.json # Archivo de salida personalizado
"""
    )

    # Modos de operación
    operation_group = parser.add_argument_group('Modos de Operación')
    operation_group.add_argument(
        '--collect-only',
        action='store_true',
        help='Solo ejecutar recolección de datos (sin análisis)'
    )
    operation_group.add_argument(
        '--analyze-only',
        action='store_true',
        help='Solo ejecutar análisis (requiere archivo de datos previo)'
    )
    operation_group.add_argument(
        '--input',
        type=str,
        help='Archivo JSON de entrada para modo --analyze-only'
    )

    # Opciones de recolección específica
    collection_group = parser.add_argument_group('Opciones de Recolección')
    collection_group.add_argument(
        '--check-vpcs-only',
        action='store_true',
        help='Solo verificar VPCs y subnets'
    )
    collection_group.add_argument(
        '--check-sgs-only',
        action='store_true',
        help='Solo verificar Security Groups'
    )
    collection_group.add_argument(
        '--check-exposed-only',
        action='store_true',
        help='Solo verificar recursos expuestos a Internet'
    )
    collection_group.add_argument(
        '--check-elbs-only',
        action='store_true',
        help='Solo verificar Load Balancers'
    )
    collection_group.add_argument(
        '--check-flow-logs-only',
        action='store_true',
        help='Solo verificar Flow Logs'
    )
    collection_group.add_argument(
        '--region',
        type=str,
        help='Analizar solo una región específica (ej: LA-Santiago)'
    )

    # Opciones de salida
    output_group = parser.add_argument_group('Opciones de Salida')
    output_group.add_argument(
        '--output',
        type=str,
        help='Archivo de salida para los resultados (default: network_results_TIMESTAMP.json)'
    )
    output_group.add_argument(
        '--simple-output',
        action='store_true',
        help='Usar nombre de archivo simple (network_results.json)'
    )
    output_group.add_argument(
        '--no-save',
        action='store_true',
        help='No guardar resultados en archivo'
    )
    output_group.add_argument(
        '--format',
        choices=['json', 'summary', 'detailed'],
        default='json',
        help='Formato de salida (default: json)'
    )

    # Opciones generales
    general_group = parser.add_argument_group('Opciones Generales')
    general_group.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Mostrar información detallada durante la ejecución'
    )
    general_group.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Modo silencioso - solo mostrar errores'
    )
    general_group.add_argument(
        '--dry-run',
        action='store_true',
        help='Ejecutar sin realizar cambios ni guardar archivos'
    )

    return parser


def get_output_path(args):
    """Determinar la ruta del archivo de salida"""
    # Directorio de salida
    base_dir = Path("results/network")
    base_dir.mkdir(parents=True, exist_ok=True)

    # Nombre del archivo
    if args.output:
        file_name = Path(args.output).name  # evitamos rutas externas
    elif args.simple_output:
        file_name = "network_results.json"
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"network_results_{timestamp}.json"

    return str(base_dir / file_name)


async def run_collection(args):
    """Ejecutar la recolección según las opciones especificadas"""
    try:
        # Importar el colector
        from collectors.network_collector import NetworkCollector
        collector = NetworkCollector()

        print("✅ Colector Network inicializado correctamente")

        # Determinar qué recolectar según las opciones
        if args.check_vpcs_only:
            print("📋 Modo: Solo VPCs y Subnets")
            results = {
                'vpcs': {},
                'subnets': {},
                'timestamp': datetime.now().isoformat()
            }

            regions = [
                args.region] if args.region else collector.region_map.keys()
            for region in regions:
                vpcs = await collector._collect_vpcs(region)
                if vpcs:
                    results['vpcs'][region] = vpcs

                subnets = await collector._collect_subnets(region)
                if subnets:
                    results['subnets'][region] = subnets

        elif args.check_sgs_only:
            print("📋 Modo: Solo Security Groups")
            results = {
                'security_groups': {},
                'timestamp': datetime.now().isoformat()
            }

            regions = [
                args.region] if args.region else collector.region_map.keys()
            for region in regions:
                sgs = await collector._collect_security_groups(region)
                if sgs:
                    results['security_groups'][region] = sgs

        elif args.check_exposed_only:
            print("📋 Modo: Solo recursos expuestos")
            results = {
                'exposed_resources': [],
                'timestamp': datetime.now().isoformat()
            }

            regions = [
                args.region] if args.region else collector.region_map.keys()
            for region in regions:
                exposed = await collector._analyze_exposed_resources(region)
                if exposed:
                    results['exposed_resources'].extend(exposed)

        elif args.check_elbs_only:
            print("📋 Modo: Solo Load Balancers")
            results = {
                'load_balancers': {},
                'timestamp': datetime.now().isoformat()
            }

            regions = [
                args.region] if args.region else collector.region_map.keys()
            for region in regions:
                elbs = await collector._collect_load_balancers(region)
                if elbs:
                    results['load_balancers'][region] = elbs

        elif args.check_flow_logs_only:
            print("📋 Modo: Solo Flow Logs")
            results = {
                'flow_logs': {},
                'timestamp': datetime.now().isoformat()
            }

            regions = [
                args.region] if args.region else collector.region_map.keys()
            for region in regions:
                flow_logs = await collector._collect_flow_logs(region)
                if flow_logs:
                    results['flow_logs'][region] = flow_logs

        else:
            # Recolección completa
            print("📋 Modo: Recolección completa de red")
            results = await collector.collect_all()

        return results

    except ImportError as e:
        print(f"❌ ERROR: No se pudo importar NetworkCollector")
        print(f"   Detalles: {e}")
        print(f"   Asegúrese de estar en el directorio raíz del proyecto")
        return None

    except Exception as e:
        print(f"❌ ERROR durante la recolección: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return None


async def run_analysis(data, args):
    """Ejecutar el análisis de vulnerabilidades"""
    try:
        # Intentar importar el analizador específico de Network
        try:
            from analyzers import ModuleVulnerabilityAnalyzer
            analyzer = ModuleVulnerabilityAnalyzer()
            print("⚠️ Usando ModuleVulnerabilityAnalyzer (compatibilidad)")
        except ImportError:
            # Fallback al analizador combinado
            try:
                from analyzers import ModuleVulnerabilityAnalyzer
                analyzer = ModuleVulnerabilityAnalyzer()
                print("⚠️ Usando ModuleVulnerabilityAnalyzer (compatibilidad)")
            except ImportError:
                print(
                    "⚠️ ADVERTENCIA: No se pudo importar analizador de vulnerabilidades")
                return None

        # Ejecutar análisis
        print("🔍 Ejecutando análisis de vulnerabilidades de red...")
        analyzer.analyze(data)  # or analyzer.analyze_network_vulnerabilities(data) if it exists

        # Obtener resultados
        vulnerabilities = analyzer.get_vulnerabilities()
        vuln_by_severity = analyzer.get_vulnerabilities_by_severity()
        vuln_by_type = analyzer.get_vulnerabilities_by_type()

        analysis_results = {
            'total_vulnerabilities': len(vulnerabilities),
            'by_severity': vuln_by_severity,
            'by_type': vuln_by_type,
            'vulnerabilities': [
                {
                    'id': v.id,
                    'title': v.title,
                    'description': v.description,
                    'severity': v.severity,
                    'cvss_score': v.cvss_score,
                    'affected_resources': v.affected_resources,
                    'remediation': v.remediation
                }
                for v in vulnerabilities
            ]
        }

        return analysis_results

    except Exception as e:
        print(f"❌ ERROR durante el análisis: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return None


def print_summary(results, analysis=None):
    """Imprimir resumen de resultados"""
    print("\n" + "="*60)
    print("📊 RESUMEN DE RESULTADOS")
    print("="*60)

    if results:
        # Estadísticas de recolección
        if 'statistics' in results:
            stats = results['statistics']
            print("\n📈 Estadísticas de Recolección:")

            if 'collected' in stats:
                collected = stats['collected']
                print(f"  • VPCs analizadas: {collected.get('vpcs', 0)}")
                print(f"  • Subnets analizadas: {collected.get('subnets', 0)}")
                print(
                    f"  • Security Groups: {collected.get('security_groups', 0)}")
                print(
                    f"  • Load Balancers: {collected.get('load_balancers', 0)}")
                print(f"  • Flow Logs: {collected.get('flow_logs', 0)}")
                print(
                    f"  • Recursos expuestos: {collected.get('exposed_resources', 0)}")
                print(
                    f"  • Regiones analizadas: {collected.get('regions_analyzed', 0)}")

        # Hallazgos
        if 'findings' in results:
            findings = results['findings']
            print(f"\n🔍 Hallazgos de Seguridad: {len(findings)}")

            # Agrupar por severidad
            by_severity = {}
            for f in findings:
                sev = f.get('severity', 'UNKNOWN')
                by_severity[sev] = by_severity.get(sev, 0) + 1

            for sev in ['CRITICA', 'ALTA', 'MEDIA', 'BAJA']:
                if sev in by_severity:
                    icon = {'CRITICA': '🔴', 'ALTA': '🟠',
                            'MEDIA': '🟡', 'BAJA': '🟢'}.get(sev, '⚪')
                    print(f"  {icon} {sev}: {by_severity[sev]}")

            # Top hallazgos críticos
            critical = [f for f in findings if f.get('severity') == 'CRITICA']
            if critical:
                print("\n⚠️ Hallazgos Críticos:")
                for f in critical[:5]:  # Mostrar hasta 5
                    print(f"  • [{f['id']}] {f['message']}")

    # Resultados del análisis
    if analysis:
        print(f"\n🛡️ Análisis de Vulnerabilidades:")
        print(
            f"  • Total de vulnerabilidades: {analysis.get('total_vulnerabilities', 0)}")

        if 'by_severity' in analysis:
            print("  • Por severidad:")
            for sev, count in analysis['by_severity'].items():
                print(f"    - {sev}: {count}")

    print("\n" + "="*60)


def save_results(results, output_path, args):
    """Guardar resultados en archivo"""
    if args.dry_run or args.no_save:
        if args.dry_run:
            print("🔧 Modo dry-run: No se guardarán archivos")
        return

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)

        print(f"\n💾 Resultados guardados en: {output_path}")

        # Mostrar tamaño del archivo
        file_size = Path(output_path).stat().st_size
        if file_size > 1024 * 1024:
            print(f"   Tamaño: {file_size / (1024*1024):.2f} MB")
        else:
            print(f"   Tamaño: {file_size / 1024:.2f} KB")

    except Exception as e:
        print(f"❌ ERROR al guardar resultados: {e}")


async def main():
    """Función principal del CLI"""
    # Configurar argumentos
    parser = setup_argument_parser()
    args = parser.parse_args()

    # Mostrar banner (excepto en modo quiet)
    if not args.quiet:
        print_banner()

    # Validar argumentos conflictivos
    if args.collect_only and args.analyze_only:
        print("❌ ERROR: No se pueden usar --collect-only y --analyze-only al mismo tiempo")
        sys.exit(1)

    if args.analyze_only and not args.input:
        print(
            "❌ ERROR: --analyze-only requiere especificar --input con un archivo de datos")
        sys.exit(1)

    # Ejecutar según el modo
    results = None
    analysis = None

    # Modo análisis solo
    if args.analyze_only:
        print(f"📂 Cargando datos desde: {args.input}")
        try:
            with open(args.input, 'r', encoding='utf-8') as f:
                results = json.load(f)
            print("✅ Datos cargados correctamente")
        except Exception as e:
            print(f"❌ ERROR al cargar archivo: {e}")
            sys.exit(1)

        # Ejecutar análisis
        analysis = await run_analysis(results, args)

    # Modo recolección (con o sin análisis)
    else:
        # Ejecutar recolección
        results = await run_collection(args)

        if results and not args.collect_only:
            # Ejecutar análisis si no es modo collect-only
            analysis = await run_analysis(results, args)

    # Procesar resultados
    if results:
        # Agregar análisis a los resultados si existe
        if analysis:
            results['vulnerability_analysis'] = analysis

        # Mostrar resumen (excepto en modo quiet)
        if not args.quiet:
            if args.format == 'summary' or args.format == 'detailed':
                print_summary(results, analysis)
            elif args.verbose:
                # En modo verbose con formato json, mostrar un resumen también
                print_summary(results, analysis)

        # Guardar resultados
        if not args.no_save:
            output_path = get_output_path(args)
            save_results(results, output_path, args)

        # Retornar código de salida basado en hallazgos críticos
        if 'findings' in results:
            critical_findings = [f for f in results['findings']
                                 if f.get('severity') == 'CRITICA']
            if critical_findings:
                if not args.quiet:
                    print(
                        f"\n⚠️ Se encontraron {len(critical_findings)} hallazgos CRÍTICOS")
                sys.exit(2)  # Código de salida 2 para hallazgos críticos

        print("\n✅ Proceso completado exitosamente")
        sys.exit(0)

    else:
        print("\n❌ No se obtuvieron resultados")
        sys.exit(1)


if __name__ == "__main__":
    # Configurar el loop de eventos para asyncio
    try:
        if sys.platform == 'win32':
            # En Windows, usar el selector de eventos
            asyncio.set_event_loop_policy(
                asyncio.WindowsSelectorEventLoopPolicy())

        # Ejecutar la función principal
        asyncio.run(main())

    except KeyboardInterrupt:
        print("\n\n⚠️ Proceso interrumpido por el usuario")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ ERROR FATAL: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
