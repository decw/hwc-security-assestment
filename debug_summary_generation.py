#!/usr/bin/env python3
"""
Debug específico para la generación del summary
"""

import json
import traceback
import sys
from pathlib import Path
from utils.iam_report_generator import IAMReportGenerator


def debug_summary_step_by_step():
    """Debug paso a paso de la generación del summary"""
    print("🔍 DEBUG: Generación de Summary IAM")

    # Cargar datos del archivo más reciente
    data_file = 'reports/iam/iam_results_20250818_023346.json'
    print(f"\n📂 Cargando datos desde: {data_file}")

    try:
        with open(data_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print("✅ Datos cargados exitosamente")
        print(f"   Tamaño del archivo: {Path(data_file).stat().st_size} bytes")
    except Exception as e:
        print(f"❌ Error cargando datos: {e}")
        return

    # Verificar estructura de datos críticos
    print(f"\n📊 Verificando estructura de datos:")
    critical_fields = ['users', 'groups', 'roles', 'policies',
                       'access_keys', 'mfa_status', 'findings', 'statistics']

    for field in critical_fields:
        if field in data:
            if isinstance(data[field], list):
                print(f"  ✅ {field}: {len(data[field])} elementos")
            elif isinstance(data[field], dict):
                print(
                    f"  ✅ {field}: diccionario con {len(data[field])} claves")
            else:
                print(f"  ✅ {field}: {type(data[field])}")
        else:
            print(f"  ❌ {field}: FALTANTE")

    # Crear generador
    print(f"\n🔧 Creando generador de reportes...")
    try:
        generator = IAMReportGenerator(data)
        print("✅ Generador creado exitosamente")
    except Exception as e:
        print(f"❌ Error creando generador: {e}")
        traceback.print_exc()
        return

    # Probar generación del header
    print(f"\n🧪 Probando generación del header...")
    try:
        header = generator._generate_header()
        print(f"✅ Header generado: {len(header)} caracteres")
    except Exception as e:
        print(f"❌ Error en header: {e}")
        traceback.print_exc()
        return

    # Probar generación del resumen ejecutivo
    print(f"\n🧪 Probando resumen ejecutivo...")
    try:
        exec_summary = generator._generate_executive_summary()
        print(f"✅ Resumen ejecutivo generado: {len(exec_summary)} caracteres")
    except Exception as e:
        print(f"❌ Error en resumen ejecutivo: {e}")
        traceback.print_exc()
        return

    # Probar cada sección individual
    sections = [
        ('Usuarios', generator._generate_users_section),
        ('Grupos', generator._generate_groups_section),
        ('Roles', generator._generate_roles_section),
        ('Políticas', generator._generate_policies_section),
        ('MFA', generator._generate_mfa_section),
        ('Access Keys', generator._generate_access_keys_section),
        ('Security Findings', generator._generate_security_findings_section),
        ('Statistics', generator._generate_statistics_section),
        ('Recommendations', generator._generate_recommendations_section),
        ('Annexes', generator._generate_annexes)
    ]

    print(f"\n🧪 Probando cada sección individual:")

    for section_name, section_func in sections:
        try:
            print(f"  🔄 Generando: {section_name}")
            content = section_func()
            print(f"    ✅ {section_name}: {len(content)} caracteres")

            if len(content) < 50:
                print(f"    ⚠️ Contenido muy corto para {section_name}")
                print(f"    📝 Contenido: {content[:100]}...")

        except Exception as e:
            print(f"    ❌ ERROR en {section_name}: {e}")
            traceback.print_exc()
            print(f"    🛑 FALLO DETECTADO EN: {section_name}")
            return section_name

    # Si llegamos aquí, todas las secciones funcionan individualmente
    print(f"\n✅ Todas las secciones se generan correctamente por separado")

    # Ahora probar la generación completa
    print(f"\n🎯 Probando generación completa del summary...")
    try:
        output_path = Path('reports/iam/')
        summary_path = generator._generate_detailed_summary(output_path)

        print(f"✅ Summary generado en: {summary_path}")

        # Verificar tamaño
        if summary_path.exists():
            size = summary_path.stat().st_size
            print(f"📏 Tamaño final: {size} bytes")

            if size < 1000:
                print("❌ ARCHIVO MUY PEQUEÑO - Error durante escritura")

                # Leer contenido para debug
                with open(summary_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                print(f"📝 Contenido actual ({len(content)} chars):")
                print(content)
            else:
                print("✅ Archivo parece completo")

                # Contar líneas
                with open(summary_path, 'r', encoding='utf-8') as f:
                    lines = len(f.readlines())
                print(f"📏 Total de líneas: {lines}")

    except Exception as e:
        print(f"❌ Error en generación completa: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    debug_summary_step_by_step()
