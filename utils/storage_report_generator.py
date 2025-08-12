#!/usr/bin/env python3
"""
Storage Report Generator
Genera reportes detallados de hallazgos de seguridad en almacenamiento
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import pandas as pd


class StorageReportGenerator:
    """Generador de reportes para el dominio Storage"""

    def __init__(self, output_dir: str = "reports/storage"):
        """
        Inicializar el generador de reportes

        Args:
            output_dir: Directorio donde se guardarán los reportes
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate_all_reports(self,
                             collection_data: Dict,
                             analysis_data: Optional[Dict] = None,
                             csv_path: str = 'security_references.csv') -> Dict[str, str]:
        """
        Generar todos los reportes de Storage

        Args:
            collection_data: Datos recolectados por StorageCollector
            analysis_data: Datos del análisis de vulnerabilidades
            csv_path: Ruta al archivo security_references.csv

        Returns:
            Diccionario con las rutas de los reportes generados
        """
        reports = {}

        # Generar JSON del assessment
        reports['json'] = self._generate_json_report(
            collection_data, analysis_data)

        # Generar reporte de hallazgos
        reports['findings'] = self._generate_findings_report(
            collection_data, analysis_data)

        # Generar plan de remediación
        reports['remediation'] = self._generate_remediation_plan(
            analysis_data, csv_path)

        # Generar resumen ejecutivo
        reports['summary'] = self._generate_executive_summary(
            collection_data, analysis_data)

        print(f"✅ Reportes generados en: {self.output_dir}")
        return reports

    def _generate_json_report(self, collection_data: Dict, analysis_data: Optional[Dict]) -> str:
        """
        Generar reporte JSON completo

        Args:
            collection_data: Datos recolectados
            analysis_data: Datos del análisis

        Returns:
            Ruta del archivo generado
        """
        report = {
            'assessment_info': {
                'domain': 'STORAGE',
                'timestamp': self.timestamp,
                'scope': 'Huawei Cloud Storage Services (EVS, OBS, KMS, Backup)',
                'inventory': {
                    'total_evs_volumes': 251,
                    'total_obs_buckets': 1,
                    'total_ims_images': 3,
                    'regions': ['LA-Santiago', 'LA-Buenos Aires1']
                }
            },
            'collection_data': collection_data,
            'analysis_data': analysis_data
        }

        output_file = self.output_dir / \
            f"storage_assessment_{self.timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        return str(output_file)

    def _generate_findings_report(self, collection_data: Dict, analysis_data: Optional[Dict]) -> str:
        """
        Generar reporte de hallazgos en Markdown

        Args:
            collection_data: Datos recolectados
            analysis_data: Datos del análisis

        Returns:
            Ruta del archivo generado
        """
        markdown = []
        markdown.append("# 🔒 Reporte de Hallazgos - Dominio STORAGE")
        markdown.append(
            f"\n**Fecha**: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        markdown.append(f"**Cliente**: CAMUZZI GAS PAMPEANA S.A.")
        markdown.append(f"**Plataforma**: Huawei Cloud")
        markdown.append(f"**Alcance**: 251 EVS, 1 OBS, KMS, Backup Services\n")

        # Resumen ejecutivo
        markdown.append("## 📊 Resumen Ejecutivo\n")

        if analysis_data and 'summary' in analysis_data:
            summary = analysis_data['summary']
            total_vulns = summary.get('total_vulnerabilities', 0)

            markdown.append(
                f"Se identificaron **{total_vulns} vulnerabilidades** en la configuración de almacenamiento:\n")

            # Tabla de severidades
            markdown.append("| Severidad | Cantidad | Porcentaje |")
            markdown.append("|-----------|----------|------------|")

            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = summary['by_severity'].get(severity, 0)
                percentage = (count / total_vulns *
                              100) if total_vulns > 0 else 0
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠',
                         'MEDIUM': '🟡', 'LOW': '🟢'}[severity]
                markdown.append(
                    f"| {emoji} {severity} | {count} | {percentage:.1f}% |")

            markdown.append("")

        # Estadísticas de cobertura
        if 'statistics' in collection_data:
            stats = collection_data['statistics']
            markdown.append("### 📈 Métricas de Seguridad\n")
            markdown.append(
                f"- **Cobertura de Cifrado**: {stats.get('encryption_coverage', 0)}%")
            markdown.append(
                f"- **Cobertura de Backup**: {stats.get('backup_coverage', 0)}%")
            markdown.append(
                f"- **Volúmenes sin cifrar**: {stats.get('unencrypted_volumes', 0)}/{stats.get('total_evs_volumes', 251)}")
            markdown.append(
                f"- **Buckets públicos**: {stats.get('public_buckets', 0)}/{stats.get('total_obs_buckets', 1)}")
            markdown.append(
                f"- **KMS Keys sin rotación**: {stats.get('kms_keys_not_rotated', 0)}")
            markdown.append("")

        # Hallazgos detallados
        markdown.append("## 🔍 Hallazgos Detallados\n")

        if analysis_data and 'vulnerabilities' in analysis_data:
            for vuln in analysis_data['vulnerabilities']:
                severity_emoji = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }.get(vuln['severity'], '⚪')

                markdown.append(
                    f"### {severity_emoji} [{vuln['code']}] {vuln['title']}")
                markdown.append(
                    f"\n**Severidad**: {vuln['severity']} | **CVSS**: {vuln.get('cvss_score', 'N/A')}")
                markdown.append(
                    f"**Recursos Afectados**: {vuln.get('affected_resources_count', 0)}")

                if vuln.get('description'):
                    markdown.append(f"\n**Descripción**:")
                    markdown.append(f"{vuln['description']}")

                if vuln.get('evidence'):
                    markdown.append(f"\n**Evidencia**:")
                    # Mostrar muestra de evidencia
                    evidence = vuln['evidence']
                    for key, value in evidence.items():
                        if isinstance(value, list) and value:
                            markdown.append(
                                f"- {key}: {len(value)} items encontrados")
                            # Mostrar primeros 3 items como ejemplo
                            for item in value[:3]:
                                if isinstance(item, dict):
                                    markdown.append(
                                        f"  - {item.get('id', item.get('name', 'N/A'))}")

                if vuln.get('recommendation'):
                    markdown.append(f"\n**Recomendación**:")
                    markdown.append(f"{vuln['recommendation']}")

                if vuln.get('compliance_mapping'):
                    mappings = [f"{k}: {v}" for k,
                                v in vuln['compliance_mapping'].items() if v]
                    if mappings:
                        markdown.append(
                            f"\n**Compliance**: {' | '.join(mappings)}")

                markdown.append("\n---\n")

        # Hallazgos por región
        markdown.append("## 🌍 Distribución Regional\n")

        regions_data = {}
        for region in ['LA-Santiago', 'LA-Buenos Aires1']:
            evs_count = len(collection_data.get(
                'evs_volumes', {}).get(region, []))
            obs_count = len(collection_data.get(
                'obs_buckets', {}).get(region, []))
            kms_count = len(collection_data.get(
                'kms_keys', {}).get(region, []))

            if evs_count or obs_count or kms_count:
                regions_data[region] = {
                    'EVS': evs_count,
                    'OBS': obs_count,
                    'KMS': kms_count
                }

        if regions_data:
            markdown.append("| Región | EVS | OBS | KMS |")
            markdown.append("|--------|-----|-----|-----|")
            for region, counts in regions_data.items():
                markdown.append(
                    f"| {region} | {counts['EVS']} | {counts['OBS']} | {counts['KMS']} |")

        # Guardar archivo
        output_file = self.output_dir / f"storage_findings_{self.timestamp}.md"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(markdown))

        return str(output_file)

    def _generate_remediation_plan(self, analysis_data: Optional[Dict], csv_path: str) -> str:
        """
        Generar plan de remediación basado en prioridades

        Args:
            analysis_data: Datos del análisis
            csv_path: Ruta al archivo CSV con referencias

        Returns:
            Ruta del archivo generado
        """
        markdown = []
        markdown.append("# 🛠️ Plan de Remediación - Dominio STORAGE")
        markdown.append(
            f"\n**Fecha**: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        markdown.append(f"**Cliente**: CAMUZZI GAS PAMPEANA S.A.")
        markdown.append(
            f"**Objetivo**: Remediar vulnerabilidades de almacenamiento en 90 días\n")

        # Cargar referencias del CSV si existe
        controls_ref = {}
        try:
            if os.path.exists(csv_path):
                df = pd.read_csv(csv_path)
                storage_df = df[df['Dominio'] == 'STORAGE']
                for _, row in storage_df.iterrows():
                    controls_ref[row['Codigo']] = {
                        'tiempo_remediacion': int(row['Tiempo_Remediacion_Dias']) if pd.notna(row['Tiempo_Remediacion_Dias']) else 30,
                        'esfuerzo': int(row['Esfuerzo_Horas']) if pd.notna(row['Esfuerzo_Horas']) else 4
                    }
        except:
            pass

        if analysis_data and 'vulnerabilities' in analysis_data:
            # Agrupar por severidad
            by_severity = {
                'CRITICAL': [],
                'HIGH': [],
                'MEDIUM': [],
                'LOW': []
            }

            for vuln in analysis_data['vulnerabilities']:
                severity = vuln.get('severity', 'LOW')
                by_severity[severity].append(vuln)

            # Fase 1: Críticas (0-7 días)
            if by_severity['CRITICAL']:
                markdown.append(
                    "## 🔴 FASE 1: Vulnerabilidades Críticas (0-7 días)\n")
                markdown.append(
                    "**Objetivo**: Mitigar riesgos inmediatos de seguridad\n")

                total_hours = 0
                for vuln in by_severity['CRITICAL']:
                    code = vuln['code']
                    effort = vuln.get('remediation_effort', {}).get('hours', 4)
                    total_hours += effort

                    markdown.append(f"### {code}: {vuln['title']}")
                    markdown.append(f"- **Esfuerzo estimado**: {effort} horas")
                    markdown.append(
                        f"- **Recursos afectados**: {vuln.get('affected_resources_count', 0)}")
                    markdown.append(
                        f"- **Acción inmediata**: {vuln.get('recommendation', 'Aplicar configuración recomendada')}")
                    markdown.append("")

                markdown.append(
                    f"**Total Fase 1**: {total_hours} horas de esfuerzo\n")

            # Fase 2: Altas (7-30 días)
            if by_severity['HIGH']:
                markdown.append(
                    "## 🟠 FASE 2: Vulnerabilidades Altas (7-30 días)\n")
                markdown.append(
                    "**Objetivo**: Fortalecer controles de seguridad\n")

                total_hours = 0
                for vuln in by_severity['HIGH']:
                    code = vuln['code']
                    effort = vuln.get('remediation_effort', {}).get('hours', 4)
                    total_hours += effort

                    markdown.append(f"### {code}: {vuln['title']}")
                    markdown.append(f"- **Esfuerzo estimado**: {effort} horas")
                    markdown.append(
                        f"- **Recursos afectados**: {vuln.get('affected_resources_count', 0)}")
                    markdown.append(
                        f"- **Acción**: {vuln.get('recommendation', 'Aplicar configuración recomendada')}")
                    markdown.append("")

                markdown.append(
                    f"**Total Fase 2**: {total_hours} horas de esfuerzo\n")

            # Fase 3: Medias (30-60 días)
            if by_severity['MEDIUM']:
                markdown.append(
                    "## 🟡 FASE 3: Vulnerabilidades Medias (30-60 días)\n")
                markdown.append(
                    "**Objetivo**: Optimizar configuraciones y políticas\n")

                total_hours = 0
                for vuln in by_severity['MEDIUM']:
                    code = vuln['code']
                    effort = vuln.get('remediation_effort', {}).get('hours', 4)
                    total_hours += effort

                    markdown.append(f"### {code}: {vuln['title']}")
                    markdown.append(f"- **Esfuerzo estimado**: {effort} horas")
                    markdown.append(
                        f"- **Recursos afectados**: {vuln.get('affected_resources_count', 0)}")
                    markdown.append(
                        f"- **Acción**: {vuln.get('recommendation', 'Aplicar configuración recomendada')}")
                    markdown.append("")

                markdown.append(
                    f"**Total Fase 3**: {total_hours} horas de esfuerzo\n")

            # Fase 4: Bajas (60-90 días)
            if by_severity['LOW']:
                markdown.append(
                    "## 🟢 FASE 4: Vulnerabilidades Bajas (60-90 días)\n")
                markdown.append(
                    "**Objetivo**: Mejora continua y optimización de costos\n")

                total_hours = 0
                for vuln in by_severity['LOW']:
                    code = vuln['code']
                    effort = vuln.get('remediation_effort', {}).get('hours', 4)
                    total_hours += effort

                    markdown.append(f"### {code}: {vuln['title']}")
                    markdown.append(f"- **Esfuerzo estimado**: {effort} horas")
                    markdown.append(
                        f"- **Recursos afectados**: {vuln.get('affected_resources_count', 0)}")
                    markdown.append(
                        f"- **Acción**: {vuln.get('recommendation', 'Aplicar configuración recomendada')}")
                    markdown.append("")

                markdown.append(
                    f"**Total Fase 4**: {total_hours} horas de esfuerzo\n")

            # Resumen de esfuerzo total
            total_effort = sum(v.get('remediation_effort', {}).get(
                'hours', 0) for v in analysis_data['vulnerabilities'])
            markdown.append("## 📊 Resumen de Esfuerzo\n")
            markdown.append(
                f"- **Esfuerzo total estimado**: {total_effort} horas")
            markdown.append(f"- **Duración del plan**: 90 días")
            markdown.append(
                f"- **Recursos requeridos**: Equipo de infraestructura y seguridad")

        # Recomendaciones adicionales
        markdown.append("\n## 💡 Recomendaciones Adicionales\n")
        markdown.append(
            "1. **Implementar monitoreo continuo** de configuraciones de storage")
        markdown.append(
            "2. **Establecer políticas de cifrado** obligatorio para nuevos recursos")
        markdown.append(
            "3. **Automatizar backups** con políticas de retención adecuadas")
        markdown.append(
            "4. **Configurar alertas** para cambios en configuraciones críticas")
        markdown.append(
            "5. **Realizar auditorías periódicas** de permisos y accesos")

        # Guardar archivo
        output_file = self.output_dir / \
            f"storage_remediation_plan_{self.timestamp}.md"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(markdown))

        return str(output_file)

    def _generate_executive_summary(self, collection_data: Dict, analysis_data: Optional[Dict]) -> str:
        """
        Generar resumen ejecutivo

        Args:
            collection_data: Datos recolectados
            analysis_data: Datos del análisis

        Returns:
            Ruta del archivo generado
        """
        markdown = []
        markdown.append("# 📋 Resumen Ejecutivo - Assessment de Storage")
        markdown.append(f"\n**Fecha**: {datetime.now().strftime('%Y-%m-%d')}")
        markdown.append(f"**Cliente**: CAMUZZI GAS PAMPEANA S.A.")
        markdown.append(f"**Plataforma**: Huawei Cloud")
        markdown.append(
            f"**Servicios Evaluados**: EVS, OBS, KMS, Backup Services\n")

        # Estado actual
        markdown.append("## 🎯 Estado Actual\n")

        if 'statistics' in collection_data:
            stats = collection_data['statistics']

            # Calcular score de madurez
            encryption_score = stats.get('encryption_coverage', 0)
            backup_score = stats.get('backup_coverage', 0)
            maturity_score = (encryption_score + backup_score) / 2

            if maturity_score >= 80:
                maturity_level = "OPTIMIZADO"
                maturity_emoji = "🟢"
            elif maturity_score >= 60:
                maturity_level = "GESTIONADO"
                maturity_emoji = "🟡"
            elif maturity_score >= 40:
                maturity_level = "DEFINIDO"
                maturity_emoji = "🟠"
            else:
                maturity_level = "INICIAL"
                maturity_emoji = "🔴"

            markdown.append(
                f"**Nivel de Madurez**: {maturity_emoji} {maturity_level} ({maturity_score:.1f}%)\n")

            # Métricas clave
            markdown.append("### Métricas Clave\n")
            markdown.append("| Métrica | Valor | Estado |")
            markdown.append("|---------|-------|--------|")

            # Cifrado
            enc_status = "✅" if encryption_score > 80 else "⚠️" if encryption_score > 50 else "❌"
            markdown.append(
                f"| Cobertura de Cifrado | {encryption_score:.1f}% | {enc_status} |")

            # Backup
            bkp_status = "✅" if backup_score > 80 else "⚠️" if backup_score > 50 else "❌"
            markdown.append(
                f"| Cobertura de Backup | {backup_score:.1f}% | {bkp_status} |")

            # Volúmenes
            total_evs = stats.get('total_evs_volumes', 251)
            unencrypted = stats.get('unencrypted_volumes', 0)
            evs_status = "✅" if unencrypted == 0 else "⚠️" if unencrypted < 10 else "❌"
            markdown.append(
                f"| Volúmenes sin Cifrar | {unencrypted}/{total_evs} | {evs_status} |")

            # Buckets públicos
            public = stats.get('public_buckets', 0)
            bucket_status = "✅" if public == 0 else "❌"
            markdown.append(
                f"| Buckets Públicos | {public} | {bucket_status} |")

            markdown.append("")

        # Hallazgos principales
        if analysis_data and 'summary' in analysis_data:
            summary = analysis_data['summary']

            markdown.append("## 🔍 Hallazgos Principales\n")

            total = summary.get('total_vulnerabilities', 0)
            critical = summary['by_severity'].get('CRITICAL', 0)
            high = summary['by_severity'].get('HIGH', 0)

            markdown.append(
                f"Se identificaron **{total} vulnerabilidades** que requieren atención:\n")

            if critical > 0:
                markdown.append(
                    f"- 🔴 **{critical} Críticas**: Requieren acción inmediata")
            if high > 0:
                markdown.append(f"- 🟠 **{high} Altas**: Remediar en 30 días")

            markdown.append("")

            # Top 3 riesgos
            markdown.append("### Top 3 Riesgos Identificados\n")

            if 'vulnerabilities' in analysis_data:
                top_vulns = sorted(
                    analysis_data['vulnerabilities'],
                    key=lambda x: (
                        {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2,
                            'LOW': 3}[x['severity']],
                        -x.get('affected_resources_count', 0)
                    )
                )[:3]

                for i, vuln in enumerate(top_vulns, 1):
                    markdown.append(
                        f"{i}. **{vuln['title']}** ({vuln['severity']})")
                    markdown.append(
                        f"   - Recursos afectados: {vuln.get('affected_resources_count', 0)}")

        # Recomendaciones estratégicas
        markdown.append("\n## 🎯 Recomendaciones Estratégicas\n")
        markdown.append("### Acciones Inmediatas (0-7 días)")
        markdown.append(
            "1. **Habilitar cifrado** en todos los volúmenes EVS de producción")
        markdown.append(
            "2. **Activar inmutabilidad WORM** en vaults de backup críticos")
        markdown.append("3. **Restringir acceso público** en buckets OBS")

        markdown.append("\n### Mejoras a Corto Plazo (7-30 días)")
        markdown.append("1. **Implementar rotación automática** de llaves KMS")
        markdown.append(
            "2. **Configurar políticas de backup** para todos los recursos críticos")
        markdown.append(
            "3. **Habilitar logging de acceso** en todos los buckets")

        markdown.append("\n### Optimizaciones a Medio Plazo (30-90 días)")
        markdown.append(
            "1. **Establecer políticas de lifecycle** para gestión de datos")
        markdown.append(
            "2. **Implementar replicación cross-region** para datos críticos")
        markdown.append(
            "3. **Automatizar compliance checks** mediante scripts")

        # Próximos pasos
        markdown.append("\n## ⏭️ Próximos Pasos\n")
        markdown.append(
            "1. **Revisar y aprobar** el plan de remediación propuesto")
        markdown.append("2. **Asignar recursos** para la implementación")
        markdown.append("3. **Establecer métricas** de seguimiento")
        markdown.append("4. **Programar re-assessment** en 90 días")

        # Conclusión
        markdown.append("\n## 💼 Conclusión\n")
        markdown.append(
            "El assessment de almacenamiento ha identificado oportunidades significativas ")
        markdown.append(
            "para mejorar la postura de seguridad. La implementación del plan de remediación ")
        markdown.append(
            "propuesto elevará el nivel de madurez de INICIAL/DEFINIDO a GESTIONADO en 90 días.")

        # Guardar archivo
        output_file = self.output_dir / f"storage_summary_{self.timestamp}.md"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(markdown))

        return str(output_file)


# Función de prueba
if __name__ == "__main__":
    # Datos de ejemplo para prueba
    collection_data = {
        'statistics': {
            'total_evs_volumes': 251,
            'total_obs_buckets': 1,
            'encrypted_volumes': 50,
            'unencrypted_volumes': 201,
            'encryption_coverage': 19.9,
            'backup_coverage': 25.0,
            'public_buckets': 0
        }
    }

    analysis_data = {
        'summary': {
            'total_vulnerabilities': 5,
            'by_severity': {
                'CRITICAL': 2,
                'HIGH': 1,
                'MEDIUM': 1,
                'LOW': 1
            }
        },
        'vulnerabilities': [
            {
                'code': 'STO-001',
                'title': 'Volúmenes EVS sin Cifrado',
                'severity': 'CRITICAL',
                'cvss_score': 8.6,
                'affected_resources_count': 201,
                'recommendation': 'Habilitar cifrado en todos los volúmenes',
                'remediation_effort': {'hours': 4, 'days': 7}
            }
        ]
    }

    # Generar reportes
    generator = StorageReportGenerator()
    reports = generator.generate_all_reports(collection_data, analysis_data)

    print("Reportes generados:")
    for tipo, ruta in reports.items():
        print(f"  - {tipo}: {ruta}")
