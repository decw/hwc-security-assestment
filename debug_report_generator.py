#!/usr/bin/env python3
"""
Script de debug para el generador de reportes IAM
"""

import json
import traceback
from pathlib import Path
from utils.iam_report_generator import IAMReportGenerator


def debug_report_generation():
    """Debug paso a paso del generador"""
    print("🔍 INICIANDO DEBUG DEL GENERADOR DE REPORTES")

    # Cargar datos
    data_file = 'reports/iam/iam_results_20250817_233934.json'
    print(f"\n📂 Cargando datos desde: {data_file}")

    try:
        with open(data_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print("✅ Datos cargados exitosamente")
    except Exception as e:
        print(f"❌ Error cargando datos: {e}")
        return

    # Verificar estructura de datos
    print(f"\n📊 Estructura de datos:")
    print(f"  usuarios: {len(data.get('users', []))}")
    print(f"  grupos: {len(data.get('groups', []))}")
    print(f"  roles: {len(data.get('roles', []))}")
    print(f"  políticas: {len(data.get('policies', []))}")
    print(f"  access_keys: {len(data.get('access_keys', []))}")
    print(f"  findings: {len(data.get('findings', []))}")

    # Crear generador
    print(f"\n🔧 Creando generador...")
    try:
        generator = IAMReportGenerator(data)
        print("✅ Generador creado exitosamente")
    except Exception as e:
        print(f"❌ Error creando generador: {e}")
        traceback.print_exc()
        return

    # Probar cada sección individualmente
    output_path = Path('reports/iam/')

    sections_to_test = [
        ('Header', generator._generate_header),
        ('Executive Summary', generator._generate_executive_summary),
        ('Users Section', generator._generate_users_section),
        ('Groups Section', generator._generate_groups_section),
        ('Roles Section', generator._generate_roles_section),
        ('Policies Section', generator._generate_policies_section),
        ('MFA Section', generator._generate_mfa_section),
        ('Access Keys Section', generator._generate_access_keys_section),
        ('Security Findings Section', generator._generate_security_findings_section),
        ('Statistics Section', generator._generate_statistics_section),
        ('Recommendations Section', generator._generate_recommendations_section),
        ('Annexes', generator._generate_annexes)
    ]

    print(f"\n🧪 PROBANDO CADA SECCIÓN:")

    for section_name, section_func in sections_to_test:
        try:
            print(f"\n  🔄 Probando: {section_name}")
            content = section_func()
            print(f"    ✅ {section_name}: {len(content)} caracteres generados")

            # Verificar si hay contenido
            if len(content.strip()) == 0:
                print(f"    ⚠️ {section_name}: CONTENIDO VACÍO")
            elif len(content) < 50:
                print(f"    ⚠️ {section_name}: CONTENIDO MUY CORTO")

        except Exception as e:
            print(f"    ❌ {section_name}: ERROR - {e}")
            traceback.print_exc()
            print(f"    🛑 FALLO EN SECCIÓN: {section_name}")
            break

    # Intentar generación completa
    print(f"\n🎯 INTENTANDO GENERACIÓN COMPLETA:")
    try:
        summary_path = generator._generate_detailed_summary(output_path)
        print(f"✅ Summary generado en: {summary_path}")

        # Verificar tamaño del archivo
        if summary_path.exists():
            size = summary_path.stat().st_size
            print(f"📏 Tamaño del archivo: {size} bytes")

            if size < 1000:
                print("⚠️ ARCHIVO MUY PEQUEÑO - Posible error durante generación")
            else:
                print("✅ Archivo parece completo")

    except Exception as e:
        print(f"❌ Error en generación completa: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    debug_report_generation()
