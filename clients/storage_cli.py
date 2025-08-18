#!/usr/bin/env python3
"""
CLI unificado para el colector Storage de Huawei Cloud
Importa: collectors.storage_collector y analyzers.vulnerability_analyzer_storage

Uso:
  python3 -m clients.storage_cli                    # Recolección completa
  python3 -m clients.storage_cli --help            # Ver opciones
  python3 -m clients.storage_cli --check-evs-only  # Solo EVS
  python3 -m clients.storage_cli --analyze-only    # Solo análisis
"""

import asyncio
import json
import sys
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

# Agregar el directorio raíz al path para importaciones
sys.path.append(str(Path(__file__).parent.parent))

# Ahora sí podemos importar los módulos locales
from utils.storage_report_generator import StorageReportGenerator


def print_banner():
    """Imprimir banner del script"""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║           HUAWEI CLOUD STORAGE COLLECTOR CLI             ║
    ╠═══════════════════════════════════════════════════════════╣
    ║  Recolección y análisis de almacenamiento                ║
    ║  Módulos: EVS, OBS, KMS, Backup Services                 ║
    ║  Powered by: Security Team                               ║
    ╚═══════════════════════════════════════════════════════════╝
    """)


def setup_argument_parser():
    """Configurar parser de argumentos de línea de comandos"""
    parser = argparse.ArgumentParser(
        description='CLI unificado para Storage - Recolección y Análisis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python3 -m clients.storage_cli                         # Recolección completa + análisis
  python3 -m clients.storage_cli --collect-only          # Solo recolección
  python3 -m clients.storage_cli --analyze-only          # Solo análisis (requiere datos)
  python3 -m clients.storage_cli --check-evs-only        # Solo volúmenes EVS
  python3 -m clients.storage_cli --check-obs-only        # Solo buckets OBS
  python3 -m clients.storage_cli --check-kms-only        # Solo llaves KMS
  python3 -m clients.storage_cli --check-backups-only    # Solo servicios de backup
  python3 -m clients.storage_cli --region LA-Santiago    # Región específica
  python3 -m clients.storage_cli --output mi_reporte.json # Archivo personalizado
  python3 -m clients.storage_cli --verbose --no-confirm  # Modo detallado sin confirmación
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
        '--check-evs-only',
        action='store_true',
        help='Solo verificar volúmenes EVS'
    )

    parser.add_argument(
        '--check-obs-only',
        action='store_true',
        help='Solo verificar buckets OBS'
    )

    parser.add_argument(
        '--check-kms-only',
        action='store_true',
        help='Solo verificar llaves KMS'
    )

    parser.add_argument(
        '--check-backups-only',
        action='store_true',
        help='Solo verificar servicios de backup (CSBS/VBS)'
    )

    parser.add_argument(
        '--check-snapshots-only',
        action='store_true',
        help='Solo verificar snapshots'
    )

    # Filtros de región
    parser.add_argument(
        '--region', '-r',
        type=str,
        help='Analizar solo una región específica (ej: LA-Santiago)'
    )

    parser.add_argument(
        '--skip-regions',
        nargs='+',
        help='Omitir regiones específicas (ej: CN-Hong_Kong AP-Bangkok)'
    )

    # Opciones de salida
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Archivo de salida (default: storage_results_TIMESTAMP.json)'
    )

    parser.add_argument(
        '--simple-output',
        action='store_true',
        help='Guardar con nombre simple (storage_results.json)'
    )

    # Opciones de verbosidad
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Modo verbose con información detallada'
    )

    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Modo silencioso, solo errores'
    )

    # Opciones adicionales
    parser.add_argument(
        '--no-confirm',
        action='store_true',
        help='No solicitar confirmación antes de ejecutar'
    )

    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Deshabilitar colores en la salida'
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Timeout para operaciones de API (default: 30s)'
    )

    parser.add_argument(
        '--csv-path',
        type=str,
        default='utils/security_references.csv',
        help='Ruta al archivo security_references.csv (default: utils/security_references.csv)'
    )

    return parser


def print_colored(text: str, color: str = 'white', bold: bool = False, no_color: bool = False):
    """
    Imprimir texto con color

    Args:
        text: Texto a imprimir
        color: Color del texto
        bold: Si el texto debe ser negrita
        no_color: Si se deben deshabilitar los colores
    """
    if no_color:
        print(text)
        return

    colors = {
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m'
    }

    reset = '\033[0m'
    bold_code = '\033[1m' if bold else ''

    color_code = colors.get(color, colors['white'])
    print(f"{bold_code}{color_code}{text}{reset}")


def confirm_execution(args) -> bool:
    """
    Confirmar ejecución con el usuario

    Args:
        args: Argumentos parseados

    Returns:
        True si el usuario confirma, False si cancela
    """
    if args.no_confirm:
        return True

    print("\n⚠️  Este script recolectará información de Storage de Huawei Cloud")
    print("   Servicios incluidos: EVS, OBS, KMS, Backup Services")

    if args.region:
        print(f"   Región: {args.region}")
    else:
        print("   Regiones: LA-Santiago, LA-Buenos Aires1")

    response = input("\n¿Desea continuar? (s/n): ").lower()
    return response in ['s', 'si', 'yes', 'y']


def get_output_filename(args) -> str:
    """
    Determinar el nombre del archivo de salida

    Args:
        args: Argumentos parseados

    Returns:
        Nombre del archivo de salida
    """
    # Directorio base para salidas
    base_dir = Path('output')
    base_dir.mkdir(exist_ok=True)

    # Determinar nombre del archivo
    if args.output:
        file_name = Path(args.output).name  # evitamos rutas externas
    elif args.simple_output:
        file_name = "storage_results.json"
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"storage_results_{timestamp}.json"

    return str(base_dir / file_name)


async def run_collection(args):
    """
    Ejecutar la recolección según las opciones especificadas

    Args:
        args: Argumentos parseados
    """
    try:
        # Importar el colector
        from collectors.storage_collector import StorageCollector
        collector = StorageCollector()

        print_colored("✅ Colector Storage inicializado correctamente",
                      'green', no_color=args.no_color)

        # Determinar qué recolectar según las opciones
        if args.check_evs_only:
            print("📋 Modo: Solo volúmenes EVS")
            results = {
                'evs_volumes': {},
                'timestamp': datetime.now().isoformat()
            }

            for region in collector.region_map.keys():
                if args.region and region != args.region:
                    continue
                if args.skip_regions and region in args.skip_regions:
                    continue

                volumes = await collector._collect_evs_volumes(region)
                if volumes:
                    results['evs_volumes'][region] = volumes

        elif args.check_obs_only:
            print("📋 Modo: Solo buckets OBS")
            results = {
                'obs_buckets': {},
                'timestamp': datetime.now().isoformat()
            }

            # OBS solo en Santiago según inventario
            if not args.region or args.region == 'LA-Santiago':
                buckets = await collector._collect_obs_buckets('LA-Santiago')
                if buckets:
                    results['obs_buckets']['LA-Santiago'] = buckets

        elif args.check_kms_only:
            print("📋 Modo: Solo llaves KMS")
            results = {
                'kms_keys': {},
                'timestamp': datetime.now().isoformat()
            }

            for region in collector.region_map.keys():
                if args.region and region != args.region:
                    continue
                if args.skip_regions and region in args.skip_regions:
                    continue

                keys = await collector._collect_kms_keys(region)
                if keys:
                    results['kms_keys'][region] = keys

        elif args.check_backups_only:
            print("📋 Modo: Solo servicios de backup")
            results = {
                'backup_policies': {},
                'backup_vaults': {},
                'timestamp': datetime.now().isoformat()
            }

            for region in collector.region_map.keys():
                if args.region and region != args.region:
                    continue
                if args.skip_regions and region in args.skip_regions:
                    continue

                backup_data = await collector._collect_backup_services(region)
                if backup_data:
                    results['backup_policies'][region] = backup_data.get(
                        'policies', [])
                    results['backup_vaults'][region] = backup_data.get(
                        'vaults', [])

        elif args.check_snapshots_only:
            print("📋 Modo: Solo snapshots")
            results = {
                'snapshots': {},
                'timestamp': datetime.now().isoformat()
            }

            for region in collector.region_map.keys():
                if args.region and region != args.region:
                    continue
                if args.skip_regions and region in args.skip_regions:
                    continue

                snapshots = await collector._collect_snapshots(region)
                if snapshots:
                    results['snapshots'][region] = snapshots

        else:
            # Recolección completa
            print("📋 Modo: Recolección completa de Storage")

            if args.region:
                print(f"   Región específica: {args.region}")
            if args.skip_regions:
                print(f"   Omitiendo regiones: {', '.join(args.skip_regions)}")

            # Modificar regiones si es necesario
            if args.region:
                original_regions = collector.region_map.copy()
                collector.region_map = {
                    k: v for k, v in original_regions.items() if k == args.region}
            elif args.skip_regions:
                for region in args.skip_regions:
                    collector.region_map.pop(region, None)

            results = await collector.collect_all()

        return results

    except ImportError as e:
        print_colored(
            f"❌ ERROR: No se pudo importar StorageCollector: {str(e)}", 'red', no_color=args.no_color)
        print("   Verifique que el archivo collectors/storage_collector.py existe")
        return None

    except Exception as e:
        print_colored(
            f"❌ ERROR durante la recolección: {str(e)}", 'red', no_color=args.no_color)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return None


async def run_analysis(data: Dict, args) -> Optional[Dict]:
    """
    Ejecutar análisis de vulnerabilidades

    Args:
        data: Datos recolectados
        args: Argumentos parseados

    Returns:
        Resultados del análisis o None si hay error
    """
    try:
        # Importar el analizador
        from analyzers.vulnerability_analyzer_storage import StorageVulnerabilityAnalyzer
        from utils.storage_report_generator import StorageReportGenerator

        # Crear analizador con ruta del CSV personalizada si se proporciona
        analyzer = StorageVulnerabilityAnalyzer(csv_path=args.csv_path)

        print_colored("🔍 Iniciando análisis de vulnerabilidades...",
                      'cyan', no_color=args.no_color)

        # Ejecutar análisis
        vulnerabilities = analyzer.analyze(data)

        # Obtener resumen
        summary = analyzer.get_summary()

        # Preparar resultados
        results = {
            'vulnerabilities': analyzer.export_findings(),
            'summary': summary,
            'analysis_timestamp': datetime.now().isoformat()
        }

        # Mostrar resumen
        print_colored(f"\n📊 Resumen del Análisis:", 'yellow',
                      bold=True, no_color=args.no_color)
        print(
            f"   Total de vulnerabilidades: {summary['total_vulnerabilities']}")

        for severity, count in summary['by_severity'].items():
            if count > 0:
                color = 'red' if severity == 'CRITICAL' else 'yellow' if severity in [
                    'HIGH', 'MEDIUM'] else 'green'
                print_colored(f"   {severity}: {count}",
                              color, no_color=args.no_color)

        print(
            f"\n   Recursos afectados: {summary['total_affected_resources']}")

        # Mostrar gaps de compliance
        if any(summary['compliance_gaps'].values()):
            print("\n   Gaps de Compliance:")
            for framework, controls in summary['compliance_gaps'].items():
                if controls:
                    print(f"     {framework}: {len(controls)} controles")

        return results

    except ImportError as e:
        print_colored(f"⚠️ ADVERTENCIA: No se pudo importar StorageVulnerabilityAnalyzer",
                      'yellow', no_color=args.no_color)
        print(f"   {str(e)}")
        print("   El análisis de vulnerabilidades no estará disponible")
        return None

    except Exception as e:
        print_colored(
            f"❌ ERROR durante el análisis: {str(e)}", 'red', no_color=args.no_color)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return None


async def main():
    """Función principal del CLI"""
    # Configurar parser
    parser = setup_argument_parser()
    args = parser.parse_args()

    # Mostrar banner
    if not args.quiet:
        print_banner()

    # Validar argumentos
    if args.analyze_only and not args.input:
        print_colored("❌ ERROR: --analyze-only requiere --input con un archivo de datos",
                      'red', no_color=args.no_color)
        sys.exit(1)

    if args.collect_only and args.analyze_only:
        print_colored("❌ ERROR: No se pueden usar --collect-only y --analyze-only al mismo tiempo",
                      'red', no_color=args.no_color)
        sys.exit(1)

    # Confirmar ejecución
    if not confirm_execution(args):
        print("❌ Operación cancelada por el usuario")
        sys.exit(0)

    # Preparar estructura de resultados
    final_results = {
        'execution_info': {
            'timestamp': datetime.now().isoformat(),
            'mode': 'analyze_only' if args.analyze_only else 'collect_only' if args.collect_only else 'full',
            'args': vars(args)
        }
    }

    # Modo análisis solamente
    if args.analyze_only:
        print(f"📂 Cargando datos desde: {args.input}")
        try:
            with open(args.input, 'r') as f:
                collection_data = json.load(f)

            # Si los datos ya tienen la estructura de collection_data, extraerla
            if 'collection_data' in collection_data:
                collection_data = collection_data['collection_data']

        except FileNotFoundError:
            print_colored(
                f"❌ ERROR: Archivo {args.input} no encontrado", 'red', no_color=args.no_color)
            sys.exit(1)
        except json.JSONDecodeError:
            print_colored(
                f"❌ ERROR: El archivo {args.input} no es un JSON válido", 'red', no_color=args.no_color)
            sys.exit(1)

        # Ejecutar solo análisis
        analysis_results = await run_analysis(collection_data, args)
        if analysis_results:
            final_results['analysis_data'] = analysis_results

            # Guardar resultados del análisis
            output_file = args.output or f"storage_analysis_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_file, 'w') as f:
                json.dump(final_results, f, indent=2, default=str)

            print_colored(
                f"\n✅ Análisis completado. Resultados guardados en: {output_file}", 'green', no_color=args.no_color)
        else:
            print_colored("⚠️ No se pudo completar el análisis",
                          'yellow', no_color=args.no_color)

    else:
        # Ejecutar recolección
        print("\n🚀 Iniciando recolección de datos...")
        collection_data = await run_collection(args)

        if collection_data:
            final_results['collection_data'] = collection_data

            # Si no es modo collect_only, ejecutar análisis
            if not args.collect_only:
                print("\n" + "="*60)
                analysis_results = await run_analysis(collection_data, args)
                if analysis_results:
                    final_results['analysis_data'] = analysis_results

            # Guardar resultados
            output_file = get_output_filename(args)
            with open(output_file, 'w') as f:
                json.dump(final_results, f, indent=2, default=str)

            print_colored(f"\n✅ Proceso completado exitosamente",
                          'green', bold=True, no_color=args.no_color)
            print(f"📁 Resultados guardados en: {output_file}")

            # Mostrar estadísticas finales si están disponibles
            if 'statistics' in collection_data:
                stats = collection_data['statistics']
                print("\n📈 Estadísticas de Recolección:")
                print(f"   Total EVS: {stats.get('total_evs_volumes', 0)}")
                print(f"   Total OBS: {stats.get('total_obs_buckets', 0)}")
                print(
                    f"   Volúmenes sin cifrar: {stats.get('unencrypted_volumes', 0)}")
                print(
                    f"   Coverage de cifrado: {stats.get('encryption_coverage', 0)}%")
                print(
                    f"   Coverage de backup: {stats.get('backup_coverage', 0)}%")

            # Generar reportes en reports/storage/
            if analysis_results:
                report_generator = StorageReportGenerator()
                report_paths = report_generator.generate_all_reports(
                    collection_data,
                    analysis_results,
                    csv_path='utils/security_references.csv'
                )
                print(f"📁 Reportes detallados generados en: reports/storage/")

        else:
            print_colored("❌ No se pudieron recolectar datos",
                          'red', no_color=args.no_color)
            sys.exit(1)


if __name__ == "__main__":
    # Ejecutar función principal
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️ Operación interrumpida por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error inesperado: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
