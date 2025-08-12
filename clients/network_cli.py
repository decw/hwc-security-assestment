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
from typing import Dict, List, Any, Optional

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
    base_dir = Path("reports/network")
    base_dir.mkdir(parents=True, exist_ok=True)

    # Nombre del archivo
    if args.output:
        file_name = Path(args.output).name  # evitamos rutas externas
    elif args.simple_output:
        file_name = "network_assessment.json"
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"network_assessment_{timestamp}.json"

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
            from analyzers.vulnerability_analyzer_network import NetworkVulnerabilityAnalyzer
            analyzer = NetworkVulnerabilityAnalyzer()
            print("✅ Usando NetworkVulnerabilityAnalyzer específico")
        except ImportError as e:
            print(f"❌ Error importando NetworkVulnerabilityAnalyzer: {e}")
            # Fallback al analizador modular
            try:
                from analyzers import ModuleVulnerabilityAnalyzer
                analyzer = ModuleVulnerabilityAnalyzer()
                print("⚠️ Usando ModuleVulnerabilityAnalyzer (compatibilidad)")
            except ImportError as e2:
                print(f"❌ Error importando ModuleVulnerabilityAnalyzer: {e2}")
                print(
                    "⚠️ ADVERTENCIA: No se pudo importar ningún analizador de vulnerabilidades")
                return None

        # Ejecutar análisis
        print("🔍 Ejecutando análisis de vulnerabilidades de red...")
        analyzer.analyze_network_vulnerabilities(data)

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
    print("📊 RESUMEN DE RESULTADOS DE RED")
    print("="*60)

    if results:
        # Calcular score de seguridad
        try:
            from utils.network_report_generator import NetworkReportGenerator
            generator = NetworkReportGenerator(results)
            risk_score = generator._calculate_risk_score()
            risk_level = generator._get_risk_level(risk_score)
            print(f"\n🎯 Score de Seguridad: {risk_score}/100 ({risk_level})")
        except:
            pass

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

            # Comparación con inventario
            if 'inventory' in stats:
                inventory = stats['inventory']
                print("\n📦 Cobertura del Inventario:")
                print(
                    f"  • VPCs: {collected.get('vpcs', 0)}/{inventory.get('total_vpcs', 20)}")
                print(
                    f"  • Security Groups: {collected.get('security_groups', 0)}/{inventory.get('total_security_groups', 17)}")
                print(
                    f"  • ELBs: {collected.get('load_balancers', 0)}/{inventory.get('total_elbs', 2)}")

        # Hallazgos
        if 'findings' in results:
            findings = results['findings']
            print(f"\n🔍 Hallazgos de Seguridad: {len(findings)}")

            # Agrupar por severidad
            by_severity = {}
            by_code = {}
            for f in findings:
                sev = f.get('severity', 'UNKNOWN')
                code = f.get('id', 'UNKNOWN')
                by_severity[sev] = by_severity.get(sev, 0) + 1
                by_code[code] = by_code.get(code, 0) + 1

            for sev in ['CRITICA', 'ALTA', 'MEDIA', 'BAJA']:
                if sev in by_severity:
                    icon = {'CRITICA': '🔴', 'ALTA': '🟠',
                            'MEDIA': '🟡', 'BAJA': '🟢'}.get(sev, '⚪')
                    print(f"  {icon} {sev}: {by_severity[sev]}")

            # Hallazgos por código
            print("\n📋 Controles con Hallazgos:")
            for code in sorted(by_code.keys()):
                if code.startswith('NET-'):
                    print(f"  • {code}: {by_code[code]} ocurrencias")

            # Top hallazgos críticos
            critical = [f for f in findings if f.get('severity') == 'CRITICA']
            if critical:
                print("\n⚠️ Hallazgos Críticos:")
                for f in critical[:5]:  # Mostrar hasta 5
                    print(f"  • [{f['id']}] {f['message']}")
                if len(critical) > 5:
                    print(f"  • ... y {len(critical) - 5} más")

    # Resultados del análisis
    if analysis:
        print(f"\n🛡️ Análisis de Vulnerabilidades:")
        print(
            f"  • Total de vulnerabilidades: {analysis.get('total_vulnerabilities', 0)}")

        if 'by_severity' in analysis:
            print("  • Por severidad:")
            for sev, count in analysis['by_severity'].items():
                print(f"    - {sev}: {count}")

        if 'by_type' in analysis:
            print("  • Por tipo:")
            for vuln_type, count in list(analysis['by_type'].items())[:5]:
                print(f"    - {vuln_type}: {count}")

    # Estadísticas por región
    print("\n🌍 Resumen por Región:")
    for region in results.get('vpcs', {}).keys():
        vpcs_count = len(results.get('vpcs', {}).get(region, []))
        subnets_count = len(results.get('subnets', {}).get(region, []))
        sgs_count = len(results.get('security_groups', {}).get(region, []))
        eips_count = len(results.get('elastic_ips', {}).get(region, []))
        elbs_count = len(results.get('load_balancers', {}).get(region, []))

        print(f"  🌎 {region}:")
        print(f"     • VPCs: {vpcs_count}")
        print(f"     • Subnets: {subnets_count}")
        print(f"     • Security Groups: {sgs_count}")
        print(f"     • EIPs: {eips_count}")
        print(f"     • Load Balancers: {elbs_count}")

    print("\n" + "="*60)


def merge_collection_and_analysis(collection_data: Dict, analysis_data: Dict) -> Dict:
    """Combinar datos de recolección y análisis para reporte completo"""
    import copy
    combined = copy.deepcopy(collection_data)

    # Asegurar que existan todos los campos necesarios
    if 'statistics' not in combined:
        combined['statistics'] = {}

    # Procesar findings correctamente
    findings_by_severity = {'CRITICA': 0, 'ALTA': 0, 'MEDIA': 0, 'BAJA': 0}

    # Contar findings del collector
    if 'findings' in combined:
        for finding in combined['findings']:
            severity = finding.get('severity', 'BAJA')
            if severity in findings_by_severity:
                findings_by_severity[severity] += 1

    # Agregar vulnerabilidades del análisis
    if analysis_data:
        combined['vulnerability_analysis'] = analysis_data

        # Convertir vulnerabilidades al formato de findings
        all_findings = combined.get('findings', []).copy()

        for vuln in analysis_data.get('vulnerabilities', []):
            all_findings.append({
                'id': vuln.get('id', ''),
                'severity': vuln.get('severity', 'BAJA'),
                'message': vuln.get('title', ''),
                'details': vuln.get('description', ''),
                'timestamp': vuln.get('discovered_date', datetime.now().isoformat())
            })

            # Actualizar conteo
            severity = vuln.get('severity', 'BAJA')
            if severity in findings_by_severity:
                findings_by_severity[severity] += 1

        combined['findings'] = all_findings

    # Actualizar estadísticas
    combined['statistics']['findings_by_severity'] = findings_by_severity
    combined['statistics']['total_findings'] = sum(
        findings_by_severity.values())

    # Calcular top risks
    top_risks = []
    for finding in combined.get('findings', []):
        if finding.get('severity') in ['CRITICA', 'ALTA']:
            top_risks.append({
                'risk': finding.get('message', 'Sin descripción'),
                'severity': finding.get('severity', 'ALTA'),
                'code': finding.get('id', 'N/A')
            })
    combined['statistics']['top_risks'] = top_risks[:10]  # Top 10 riesgos

    return combined


def validate_and_fix_network_data(data: Dict) -> Dict:
    """Validar y corregir la estructura de datos de red antes de generar el reporte"""
    import copy
    from datetime import datetime

    validated_data = copy.deepcopy(data)

    # Asegurar campos esenciales
    essential_fields = {
        'vpcs': {},
        'subnets': {},
        'security_groups': {},
        'load_balancers': {},
        'flow_logs': {},
        'vpc_peerings': {},
        'network_acls': {},
        'elastic_ips': {},
        'exposed_resources': [],
        'findings': [],
        'statistics': {},
        'timestamp': datetime.now().isoformat()
    }

    for field, default_value in essential_fields.items():
        if field not in validated_data:
            validated_data[field] = default_value

    # Calcular estadísticas si no existen
    if not validated_data.get('statistics'):
        stats = {
            'collected': {
                'vpcs': sum(len(v) for v in validated_data.get('vpcs', {}).values()),
                'subnets': sum(len(s) for s in validated_data.get('subnets', {}).values()),
                'security_groups': sum(len(sg) for sg in validated_data.get('security_groups', {}).values()),
                'load_balancers': sum(len(lb) for lb in validated_data.get('load_balancers', {}).values()),
                'flow_logs': sum(len(fl) for fl in validated_data.get('flow_logs', {}).values()),
                'exposed_resources': len(validated_data.get('exposed_resources', [])),
                'regions_analyzed': len([r for r in validated_data.get('vpcs', {}) if validated_data['vpcs'][r]])
            },
            'inventory': {
                'total_vpcs': 20,
                'total_security_groups': 17,
                'total_eips': 10,
                'total_elbs': 2
            }
        }
        validated_data['statistics'] = stats

    # Contar findings por severidad
    findings_by_severity = {'CRITICA': 0, 'ALTA': 0, 'MEDIA': 0, 'BAJA': 0}
    for finding in validated_data.get('findings', []):
        severity = finding.get('severity', 'BAJA')
        if severity in findings_by_severity:
            findings_by_severity[severity] += 1

    validated_data['statistics']['findings_by_severity'] = findings_by_severity

    # Log de validación
    print("\n✅ Validación de datos de red completada:")
    print(
        f"   - VPCs: {validated_data['statistics']['collected'].get('vpcs', 0)}")
    print(
        f"   - Subnets: {validated_data['statistics']['collected'].get('subnets', 0)}")
    print(
        f"   - Security Groups: {validated_data['statistics']['collected'].get('security_groups', 0)}")
    print(
        f"   - Recursos expuestos: {validated_data['statistics']['collected'].get('exposed_resources', 0)}")
    print(f"   - Hallazgos totales: {sum(findings_by_severity.values())}")
    print(f"     • Críticos: {findings_by_severity['CRITICA']}")
    print(f"     • Altos: {findings_by_severity['ALTA']}")
    print(f"     • Medios: {findings_by_severity['MEDIA']}")
    print(f"     • Bajos: {findings_by_severity['BAJA']}")

    return validated_data


def generate_comprehensive_report(combined_data: Dict, base_output_file: str, args):
    """Generar reporte completo con datos de recolección y análisis"""
    try:
        from utils.network_report_generator import NetworkReportGenerator
        
        # Validar datos
        validated_data = validate_and_fix_network_data(combined_data)
        
        # Crear el generador de reportes
        report_generator = NetworkReportGenerator(validated_data)
        
        # Obtener directorio
        reports_dir = Path("reports/network")
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Usar el método que SÍ existe
        report_files = report_generator.generate_complete_report(str(reports_dir))
        
        print("\n📊 Reportes de Network generados:")
        for name, path in report_files.items():
            if Path(path).exists():
                size = Path(path).stat().st_size
                size_str = f"{size/1024:.1f} KB" if size < 1024*1024 else f"{size/(1024*1024):.1f} MB"
                print(f"   📋 {name.title()}: {Path(path).name} ({size_str})")
        
        return report_files
        
    except Exception as e:
        print(f"⚠️ Error generando reportes: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return {}


def save_results(results, output_path, args):
    """Guardar resultados en archivo y generar reportes detallados"""
    if args.dry_run or args.no_save:
        if args.dry_run:
            print("🔧 Modo dry-run: No se guardarán archivos")
        return True

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

        return True

    except Exception as e:
        print(f"❌ ERROR al guardar resultados: {e}")
        return False


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

        # Guardar resultados del análisis
        output_path = get_output_path(args)
        analysis_file = str(output_path).replace('.json', '_analysis.json')
        if not save_results({'analysis': analysis, 'timestamp': datetime.now().isoformat()},
                            analysis_file, args):
            sys.exit(1)

    # Modo recolección (con o sin análisis)
    else:
        # Ejecutar recolección
        results = await run_collection(args)

        if results:
            # Guardar resultados de recolección
            output_path = get_output_path(args)
            if not save_results(results, output_path, args):
                sys.exit(1)

            # Ejecutar análisis si no es modo collect-only
            if not args.collect_only:
                analysis = await run_analysis(results, args)

                if analysis:
                    # Combinar datos para el reporte completo
                    combined_results = merge_collection_and_analysis(
                        results, analysis)

                    # Generar reporte completo con datos combinados
                    generate_comprehensive_report(
                        combined_results, str(output_path), args)

                    # Guardar análisis por separado si se especificó
                    if args.verbose:
                        analysis_file = str(output_path).replace(
                            '.json', '_analysis.json')
                        save_results({'analysis': analysis, 'timestamp': datetime.now().isoformat()},
                                     analysis_file, args)
                        print(
                            f"💾 Análisis guardado por separado en: {analysis_file}")

    # Procesar resultados finales
    if results:
        # Mostrar resumen (excepto en modo quiet)
        if not args.quiet:
            if args.format == 'summary' or args.format == 'detailed':
                print_summary(results, analysis)
            elif args.verbose:
                # En modo verbose con formato json, mostrar un resumen también
                print_summary(results, analysis)

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
