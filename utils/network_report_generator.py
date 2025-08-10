#!/usr/bin/env python3
"""
Generador de reportes específico para Network
Genera JSON, resumen detallado, CSV y plan de remediación
"""

import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd

from config.settings import REPORTS_DIR, CLIENT_NAME, REPORT_TIMESTAMP
from utils.logger import SecurityLogger


class NetworkReportGenerator:
    """Generador de reportes Network con resumen detallado"""

    def __init__(self, network_results: Dict[str, Any]):
        self.results = network_results
        self.timestamp = REPORT_TIMESTAMP
        self.logger = SecurityLogger('NetworkReportGenerator')

        # Mapeo de severidades para consistencia
        self.severity_colors = {
            'CRITICA': '🔴',
            'ALTA': '🟠',
            'MEDIA': '🟡',
            'BAJA': '🟢'
        }

        # Mapeo de códigos NET a frameworks de compliance
        self.compliance_mapping = {
            'NET-001': {'CIS': '2.1', 'ISO': 'A.13.1.1', 'NIST': 'PR.AC-5'},
            'NET-002': {'CIS': '2.2', 'ISO': 'A.13.1.3', 'NIST': 'PR.AC-5'},
            'NET-003': {'CIS': '4.1-4.4', 'ISO': 'A.13.1.1', 'NIST': 'PR.AC-5'},
            'NET-004': {'CIS': '4.1-4.4', 'ISO': 'A.13.1.1', 'NIST': 'PR.AC-5'},
            'NET-005': {'CIS': '3.1-3.7', 'ISO': 'A.13.1.1', 'NIST': 'PR.AC-5'},
            'NET-006': {'CIS': '2.3', 'ISO': 'A.13.1.3', 'NIST': 'PR.AC-5'},
            'NET-007': {'CIS': '2.4', 'ISO': 'A.10.1.1', 'NIST': 'PR.DS-2'},
            'NET-008': {'CIS': '2.5', 'ISO': 'A.12.4.1', 'NIST': 'DE.CM-1'}
        }

    # --------------------------------------------------------------------- #
    # Helpers                                                               #
    # --------------------------------------------------------------------- #

    def _get_all_findings(self) -> List[Dict[str, Any]]:
        """Combinar hallazgos del collector y vulnerabilidades del analyzer"""
        findings = self.results.get('findings', []).copy()

        # Agregar vulnerabilidades del análisis si existen
        vuln_analysis = self.results.get('vulnerability_analysis', {})
        for vuln in vuln_analysis.get('vulnerabilities', []):
            findings.append({
                'id': vuln.get('id', ''),
                'severity': vuln.get('severity', 'BAJA'),
                'message': vuln.get('title', ''),
                'details': vuln.get('description', ''),
                'timestamp': vuln.get('discovered_date', datetime.now().isoformat())
            })

        return findings

    def _get_statistics(self) -> Dict[str, Any]:
        """Obtener estadísticas consolidadas"""
        stats = self.results.get('statistics', {})

        # Si no hay estadísticas, calcularlas
        if not stats:
            stats = {
                'collected': {
                    'vpcs': sum(len(v) for v in self.results.get('vpcs', {}).values()),
                    'subnets': sum(len(s) for s in self.results.get('subnets', {}).values()),
                    'security_groups': sum(len(sg) for sg in self.results.get('security_groups', {}).values()),
                    'load_balancers': sum(len(lb) for lb in self.results.get('load_balancers', {}).values()),
                    'flow_logs': sum(len(fl) for fl in self.results.get('flow_logs', {}).values()),
                    'exposed_resources': len(self.results.get('exposed_resources', []))
                },
                'inventory': {
                    'total_vpcs': 20,
                    'total_security_groups': 17,
                    'total_eips': 10,
                    'total_elbs': 2
                }
            }

        return stats

    def _calculate_risk_score(self) -> int:
        """Calcular score de riesgo de red (0-100)"""
        score = 100  # Empezar con score perfecto

        findings = self._get_all_findings()

        # Restar puntos según severidad
        for finding in findings:
            severity = finding.get('severity', 'BAJA')
            if severity == 'CRITICA':
                score -= 20
            elif severity == 'ALTA':
                score -= 10
            elif severity == 'MEDIA':
                score -= 5
            elif severity == 'BAJA':
                score -= 2

        return max(0, score)  # No permitir score negativo

    # --------------------------------------------------------------------- #
    # Generación de Reportes                                               #
    # --------------------------------------------------------------------- #

    def generate_complete_report(self, output_dir: str = None) -> Dict[str, str]:
        """Generar reporte completo: JSON + Resumen + CSV + Remediación"""
        # Usar reports/network/ como base
        network_reports_dir = REPORTS_DIR / 'network'

        if output_dir:
            output_path = Path(output_dir)
            if not str(output_path).startswith(str(REPORTS_DIR)):
                output_path = network_reports_dir
        else:
            output_path = network_reports_dir

        # Asegurar que el directorio existe
        output_path.mkdir(parents=True, exist_ok=True)

        # Generar todos los reportes
        report_files = {
            'json': self._generate_json_report(output_path),
            'summary': self._generate_detailed_summary(output_path),
            'csv': self._generate_findings_csv(output_path),
            'remediation': self._generate_remediation_plan(output_path),
            'compliance': self._generate_compliance_report(output_path)
        }

        self.logger.info(f"Reportes completos generados en: {output_path}")

        return {k: str(v) for k, v in report_files.items()}

    def _generate_json_report(self, output_path: Path) -> Path:
        """Generar reporte JSON completo"""
        json_path = output_path / f"network_assessment_{self.timestamp}.json"

        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2,
                      ensure_ascii=False, default=str)

        self.logger.info(f"Reporte JSON generado: {json_path}")
        return json_path

    def _generate_detailed_summary(self, output_path: Path) -> Path:
        """Generar resumen detallado en Markdown"""
        summary_path = output_path / f"network_summary_{self.timestamp}.md"

        with open(summary_path, 'w', encoding='utf-8') as f:
            # Header
            f.write(f"# 🌐 Assessment de Seguridad de Red - {CLIENT_NAME}\n\n")
            f.write(
                f"**Fecha**: {datetime.now().strftime('%d/%m/%Y %H:%M')}\n")
            f.write(f"**Versión**: 1.0\n")
            f.write(f"**Clasificación**: CONFIDENCIAL\n\n")

            # Score de riesgo
            risk_score = self._calculate_risk_score()
            risk_level = self._get_risk_level(risk_score)
            f.write(
                f"## 🎯 Score de Seguridad de Red: {risk_score}/100 ({risk_level})\n\n")

            # Tabla de contenidos dinámica
            f.write(self._generate_toc())

            # Resumen ejecutivo
            f.write(self._generate_executive_summary())

            # Estadísticas generales
            f.write(self._generate_statistics_section())

            # Análisis por región
            f.write(self._generate_regional_analysis())

            # VPCs y Subnets
            f.write(self._generate_vpc_section())

            # Security Groups
            f.write(self._generate_security_groups_section())

            # Recursos expuestos
            f.write(self._generate_exposed_resources_section())

            # Load Balancers
            f.write(self._generate_load_balancers_section())

            # Hallazgos críticos
            f.write(self._generate_critical_findings_section())

            # Recomendaciones
            f.write(self._generate_recommendations_section())

            # Footer
            f.write("\n---\n\n")
            f.write(
                "*Reporte generado automáticamente por Huawei Cloud Security Assessment Tool*\n")
            f.write(f"*Timestamp: {self.timestamp}*\n")

        self.logger.info(f"Resumen detallado generado: {summary_path}")
        return summary_path

    def _generate_toc(self) -> str:
        """Generar tabla de contenidos dinámica"""
        toc = "## 📋 Tabla de Contenidos\n\n"

        sections = [
            "1. [Resumen Ejecutivo](#resumen-ejecutivo)",
            "2. [Estadísticas Generales](#estadísticas-generales)",
            "3. [Análisis Regional](#análisis-regional)"
        ]

        # Agregar secciones según datos disponibles
        if self.results.get('vpcs'):
            sections.append("4. [VPCs y Segmentación](#vpcs-y-segmentación)")
        if self.results.get('security_groups'):
            sections.append("5. [Security Groups](#security-groups)")
        if self.results.get('exposed_resources'):
            sections.append("6. [Recursos Expuestos](#recursos-expuestos)")
        if self.results.get('load_balancers'):
            sections.append("7. [Load Balancers](#load-balancers)")

        sections.extend([
            "8. [Hallazgos Críticos](#hallazgos-críticos)",
            "9. [Recomendaciones](#recomendaciones)"
        ])

        for section in sections:
            toc += f"{section}\n"

        toc += "\n---\n\n"
        return toc

    def _generate_executive_summary(self) -> str:
        """Generar resumen ejecutivo"""
        findings = self._get_all_findings()
        stats = self._get_statistics()

        # Contar por severidad
        severity_counts = {
            'CRITICA': 0,
            'ALTA': 0,
            'MEDIA': 0,
            'BAJA': 0
        }

        for finding in findings:
            severity = finding.get('severity', 'BAJA')
            if severity in severity_counts:
                severity_counts[severity] += 1

        content = "## Resumen Ejecutivo\n\n"
        content += f"El assessment de seguridad de red para **{CLIENT_NAME}** ha analizado "
        content += f"**{stats['collected']['vpcs']} VPCs** distribuidas en "
        content += f"**{len(self.results.get('vpcs', {}))} regiones**.\n\n"

        content += "### 🔍 Hallazgos Principales:\n\n"

        # Hallazgos críticos
        if severity_counts['CRITICA'] > 0:
            content += f"- {self.severity_colors['CRITICA']} **{severity_counts['CRITICA']} hallazgos CRÍTICOS** que requieren atención inmediata\n"
        if severity_counts['ALTA'] > 0:
            content += f"- {self.severity_colors['ALTA']} **{severity_counts['ALTA']} hallazgos de severidad ALTA**\n"
        if severity_counts['MEDIA'] > 0:
            content += f"- {self.severity_colors['MEDIA']} **{severity_counts['MEDIA']} hallazgos de severidad MEDIA**\n"
        if severity_counts['BAJA'] > 0:
            content += f"- {self.severity_colors['BAJA']} **{severity_counts['BAJA']} hallazgos de severidad BAJA**\n"

        # Exposición
        exposed = self.results.get('exposed_resources', [])
        if exposed:
            critical_exposed = [
                r for r in exposed if r.get('critical_exposure')]
            content += f"\n### ⚠️ Exposición a Internet:\n"
            content += f"- **{len(exposed)} recursos** con IPs públicas\n"
            if critical_exposed:
                content += f"- **{len(critical_exposed)} recursos** con puertos críticos expuestos\n"

        content += "\n---\n\n"
        return content

    def _generate_statistics_section(self) -> str:
        """Generar sección de estadísticas"""
        stats = self._get_statistics()

        content = "## Estadísticas Generales\n\n"

        # Tabla de recursos analizados vs inventario
        content += "### 📊 Cobertura del Assessment\n\n"
        content += "| Recurso | Analizados | Inventario | Cobertura |\n"
        content += "|---------|------------|------------|----------|\n"

        collected = stats.get('collected', {})
        inventory = stats.get('inventory', {})

        resources = [
            ('VPCs', 'vpcs', 'total_vpcs'),
            ('Security Groups', 'security_groups', 'total_security_groups'),
            ('Load Balancers', 'load_balancers', 'total_elbs'),
            ('EIPs', 'elastic_ips', 'total_eips')
        ]

        for name, collected_key, inventory_key in resources:
            analyzed = collected.get(collected_key, 0)
            total = inventory.get(inventory_key, 0)
            coverage = (analyzed / total * 100) if total > 0 else 0
            content += f"| {name} | {analyzed} | {total} | {coverage:.1f}% |\n"

        content += "\n---\n\n"
        return content

    def _generate_regional_analysis(self) -> str:
        """Generar análisis por región"""
        content = "## Análisis Regional\n\n"

        # Obtener regiones con datos
        regions_data = {}

        # Contar recursos por región
        for region, vpcs in self.results.get('vpcs', {}).items():
            if region not in regions_data:
                regions_data[region] = {
                    'vpcs': 0,
                    'subnets': 0,
                    'security_groups': 0,
                    'findings': []
                }
            regions_data[region]['vpcs'] = len(vpcs)

        for region, subnets in self.results.get('subnets', {}).items():
            if region in regions_data:
                regions_data[region]['subnets'] = len(subnets)

        for region, sgs in self.results.get('security_groups', {}).items():
            if region in regions_data:
                regions_data[region]['security_groups'] = len(sgs)

        # Contar hallazgos por región
        for finding in self._get_all_findings():
            details = finding.get('details', {})
            if isinstance(details, dict):
                region = details.get('region')
                if region and region in regions_data:
                    regions_data[region]['findings'].append(finding)

        # Generar tabla
        content += "| Región | VPCs | Subnets | Security Groups | Hallazgos |\n"
        content += "|--------|------|---------|-----------------|----------|\n"

        for region, data in regions_data.items():
            finding_count = len(data['findings'])
            critical_count = len(
                [f for f in data['findings'] if f.get('severity') == 'CRITICA'])

            finding_str = str(finding_count)
            if critical_count > 0:
                finding_str = f"**{finding_count}** ({critical_count} críticos)"

            content += f"| {region} | {data['vpcs']} | {data['subnets']} | {data['security_groups']} | {finding_str} |\n"

        content += "\n---\n\n"
        return content

    def _generate_vpc_section(self) -> str:
        """Generar sección de VPCs y segmentación"""
        content = "## VPCs y Segmentación\n\n"

        all_vpcs = []
        for region, vpcs in self.results.get('vpcs', {}).items():
            for vpc in vpcs:
                vpc['region'] = region
                all_vpcs.append(vpc)

        if not all_vpcs:
            content += "*No se encontraron VPCs para analizar*\n\n"
            return content

        content += f"### 📈 Total de VPCs: {len(all_vpcs)}\n\n"

        # Análisis de segmentación
        content += "### 🔍 Análisis de Segmentación (NET-001)\n\n"

        vpcs_without_segregation = []
        for finding in self._get_all_findings():
            if finding.get('id') == 'NET-001':
                details = finding.get('details', {})
                if isinstance(details, dict):
                    vpcs_without_segregation.append(details)

        if vpcs_without_segregation:
            content += f"⚠️ **{len(vpcs_without_segregation)} VPCs sin segregación adecuada**\n\n"
            content += "| VPC | Región | Subnets Totales | Públicas | Privadas |\n"
            content += "|-----|--------|-----------------|----------|----------|\n"

            for vpc in vpcs_without_segregation[:10]:  # Mostrar máximo 10
                content += f"| {vpc.get('vpc_name', 'N/A')} | {vpc.get('region', 'N/A')} | "
                content += f"{vpc.get('total_subnets', 0)} | {vpc.get('public_subnets', 0)} | "
                content += f"{vpc.get('private_subnets', 0)} |\n"
        else:
            content += "✅ Todas las VPCs tienen segregación adecuada de subnets\n"

        content += "\n---\n\n"
        return content

    def _generate_security_groups_section(self) -> str:
        """Generar sección de Security Groups"""
        content = "## Security Groups\n\n"

        all_sgs = []
        for region, sgs in self.results.get('security_groups', {}).items():
            for sg in sgs:
                sg['region'] = region
                all_sgs.append(sg)

        if not all_sgs:
            content += "*No se encontraron Security Groups para analizar*\n\n"
            return content

        content += f"### 🛡️ Total de Security Groups: {len(all_sgs)}\n\n"

        # Security Groups permisivos (NET-003)
        permissive_sgs = [
            sg for sg in all_sgs if sg.get('has_permissive_rules')]

        if permissive_sgs:
            content += f"### ⚠️ Security Groups con Reglas Permisivas (NET-003)\n\n"
            content += f"**{len(permissive_sgs)} Security Groups** con reglas 0.0.0.0/0:\n\n"

            content += "| Nombre | Región | Asignaciones | Reglas Permisivas |\n"
            content += "|--------|--------|--------------|------------------|\n"

            for sg in permissive_sgs[:15]:  # Mostrar máximo 15
                permissive_count = len(
                    [r for r in sg.get('rules', []) if r.get('is_permissive')])
                content += f"| {sg.get('name', 'N/A')} | {sg.get('region', 'N/A')} | "
                content += f"{sg.get('assignments_count', 0)} | {permissive_count} |\n"
        else:
            content += "✅ No se encontraron Security Groups con reglas excesivamente permisivas\n"

        content += "\n---\n\n"
        return content

    def _generate_exposed_resources_section(self) -> str:
        """Generar sección de recursos expuestos"""
        content = "## Recursos Expuestos\n\n"

        exposed = self.results.get('exposed_resources', [])

        if not exposed:
            content += "✅ No se encontraron recursos expuestos a Internet\n\n"
            return content

        content += f"### 🌍 Total de Recursos Expuestos: {len(exposed)}\n\n"

        # Recursos con puertos críticos (NET-004)
        critical_exposed = [r for r in exposed if r.get('critical_exposure')]

        if critical_exposed:
            content += f"### 🔴 Recursos con Puertos Críticos Expuestos (NET-004)\n\n"
            content += f"**{len(critical_exposed)} recursos** con puertos sensibles abiertos:\n\n"

            content += "| Recurso | Tipo | Región | IPs Públicas | Puertos Críticos |\n"
            content += "|---------|------|--------|--------------|------------------|\n"

            for resource in critical_exposed[:10]:  # Mostrar máximo 10
                ports = [str(p.get('port', 'N/A'))
                         for p in resource.get('exposed_ports', [])]
                ips = resource.get('public_ips', [])

                content += f"| {resource.get('resource_name', 'N/A')} | "
                content += f"{resource.get('resource_type', 'N/A')} | "
                content += f"{resource.get('region', 'N/A')} | "
                content += f"{len(ips)} | "
                content += f"{', '.join(ports[:3])} |\n"

            if len(critical_exposed) > 10:
                content += f"\n*... y {len(critical_exposed) - 10} recursos más*\n"

        content += "\n---\n\n"
        return content

    def _generate_load_balancers_section(self) -> str:
        """Generar sección de Load Balancers"""
        content = "## Load Balancers\n\n"

        all_lbs = []
        for region, lbs in self.results.get('load_balancers', {}).items():
            for lb in lbs:
                lb['region'] = region
                all_lbs.append(lb)

        if not all_lbs:
            content += "*No se encontraron Load Balancers para analizar*\n\n"
            return content

        content += f"### ⚖️ Total de Load Balancers: {len(all_lbs)}\n\n"

        # Load Balancers sin SSL/TLS (NET-007)
        lbs_without_ssl = [lb for lb in all_lbs if not lb.get('has_ssl')]

        if lbs_without_ssl:
            content += f"### ⚠️ Load Balancers sin Cifrado SSL/TLS (NET-007)\n\n"
            content += f"**{len(lbs_without_ssl)} Load Balancers** sin cifrado adecuado:\n\n"

            content += "| Nombre | Región | VIP | Listeners HTTP |\n"
            content += "|--------|--------|-----|----------------|\n"

            for lb in lbs_without_ssl[:10]:
                http_count = len([l for l in lb.get('listeners', [])
                                  if l.get('protocol') in ['HTTP', 'TCP']])
                content += f"| {lb.get('name', 'N/A')} | {lb.get('region', 'N/A')} | "
                content += f"{lb.get('vip_address', 'N/A')} | {http_count} |\n"
        else:
            content += "✅ Todos los Load Balancers tienen cifrado SSL/TLS configurado\n"

        content += "\n---\n\n"
        return content

    def _generate_critical_findings_section(self) -> str:
        """Generar sección de hallazgos críticos"""
        content = "## Hallazgos Críticos\n\n"

        findings = self._get_all_findings()
        critical_findings = [
            f for f in findings if f.get('severity') == 'CRITICA']

        if not critical_findings:
            content += "✅ No se encontraron hallazgos de severidad CRÍTICA\n\n"
            return content

        content += f"### 🔴 {len(critical_findings)} Hallazgos Críticos Identificados\n\n"

        # Agrupar por código
        by_code = {}
        for finding in critical_findings:
            code = finding.get('id', 'UNKNOWN')
            if code not in by_code:
                by_code[code] = []
            by_code[code].append(finding)

        for code, code_findings in by_code.items():
            compliance = self.compliance_mapping.get(code, {})

            content += f"#### {code}: {code_findings[0].get('message', 'Sin descripción')}\n\n"
            content += f"**Cantidad**: {len(code_findings)} ocurrencias\n"

            if compliance:
                content += f"**Frameworks**: CIS {compliance.get('CIS', 'N/A')} | "
                content += f"ISO 27001 {compliance.get('ISO', 'N/A')} | "
                content += f"NIST {compliance.get('NIST', 'N/A')}\n"

            content += "\n**Detalles**:\n"
            for finding in code_findings[:3]:  # Mostrar máximo 3 por tipo
                details = finding.get('details', {})
                if isinstance(details, dict):
                    for key, value in list(details.items())[:3]:
                        if key != 'recommendation':
                            content += f"- {key}: {value}\n"

            content += "\n"

        content += "---\n\n"
        return content

    def _generate_recommendations_section(self) -> str:
        """Generar sección de recomendaciones"""
        content = "## Recomendaciones\n\n"

        findings = self._get_all_findings()

        # Recomendaciones por prioridad
        content += "### 🎯 Acciones Prioritarias\n\n"

        # Prioridad 1: Hallazgos críticos
        critical = [f for f in findings if f.get('severity') == 'CRITICA']
        if critical:
            content += "#### Prioridad 1: Inmediata (0-3 días)\n\n"

            recommendations = set()
            for finding in critical:
                details = finding.get('details', {})
                if isinstance(details, dict):
                    rec = details.get('recommendation', '')
                    if rec:
                        recommendations.add(rec)

            for i, rec in enumerate(recommendations, 1):
                content += f"{i}. {rec}\n"

            content += "\n"

        # Prioridad 2: Hallazgos altos
        high = [f for f in findings if f.get('severity') == 'ALTA']
        if high:
            content += "#### Prioridad 2: Corto Plazo (1-2 semanas)\n\n"

            recommendations = set()
            for finding in high[:10]:  # Limitar a 10
                details = finding.get('details', {})
                if isinstance(details, dict):
                    rec = details.get('recommendation', '')
                    if rec:
                        recommendations.add(rec)

            for i, rec in enumerate(recommendations, 1):
                content += f"{i}. {rec}\n"

            content += "\n"

        # Mejores prácticas generales
        content += "### 📚 Mejores Prácticas Recomendadas\n\n"
        content += "1. **Principio de Menor Privilegio**: Restringir todos los Security Groups al mínimo necesario\n"
        content += "2. **Segmentación de Red**: Implementar subnets públicas/privadas/DMZ en todas las VPCs\n"
        content += "3. **Monitoreo Continuo**: Habilitar Flow Logs y centralizar análisis de tráfico\n"
        content += "4. **Cifrado en Tránsito**: Usar SSL/TLS en todos los Load Balancers y servicios públicos\n"
        content += "5. **Defense in Depth**: Implementar Network ACLs además de Security Groups\n"
        content += "6. **Auditoría Regular**: Revisar mensualmente configuraciones de red y exposición\n"

        content += "\n---\n\n"
        return content

    def _generate_findings_csv(self, output_path: Path) -> Path:
        """Generar CSV de hallazgos de red"""
        csv_path = output_path / f"network_findings_{self.timestamp}.csv"

        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Header con campos adicionales
            writer.writerow([
                'ID', 'Severidad', 'Mensaje', 'Región', 'Recurso',
                'Detalles', 'Framework_CIS', 'Framework_ISO',
                'Framework_NIST', 'Timestamp'
            ])

            for finding in self._get_all_findings():
                code = finding.get('id', '')
                compliance = self.compliance_mapping.get(code, {})

                details = finding.get('details', {})
                region = details.get('region', 'Global') if isinstance(
                    details, dict) else 'N/A'
                resource = 'N/A'

                # Extraer recurso afectado
                if isinstance(details, dict):
                    resource = details.get('vpc_name') or details.get('sg_name') or \
                        details.get('resource_name') or details.get(
                            'lb_name') or 'N/A'

                writer.writerow([
                    code,
                    finding.get('severity', ''),
                    finding.get('message', ''),
                    region,
                    resource,
                    str(details),
                    compliance.get('CIS', ''),
                    compliance.get('ISO', ''),
                    compliance.get('NIST', ''),
                    finding.get('timestamp', '')
                ])

        self.logger.info(f"CSV de hallazgos generado: {csv_path}")
        return csv_path

    def _generate_remediation_plan(self, output_path: Path) -> Path:
        """Generar plan de remediación de red"""
        remediation_path = output_path / \
            f"network_remediation_plan_{self.timestamp}.md"

        with open(remediation_path, 'w', encoding='utf-8') as f:
            f.write(f"# 🔧 Plan de Remediación de Red - {CLIENT_NAME}\n\n")
            f.write(f"**Fecha**: {datetime.now().strftime('%d/%m/%Y')}\n")
            f.write(
                f"**Score Actual**: {self._calculate_risk_score()}/100\n\n")

            # Agrupar hallazgos por severidad y código
            severity_groups = {
                'CRITICA': [],
                'ALTA': [],
                'MEDIA': [],
                'BAJA': []
            }

            for finding in self._get_all_findings():
                severity = finding.get('severity', 'BAJA')
                if severity in severity_groups:
                    severity_groups[severity].append(finding)

            # Timeline de remediación
            f.write("## 📅 Timeline de Remediación\n\n")

            timelines = [
                ('Fase 1: Críticos (0-3 días)', 'CRITICA', 3),
                ('Fase 2: Altos (1-2 semanas)', 'ALTA', 14),
                ('Fase 3: Medios (1 mes)', 'MEDIA', 30),
                ('Fase 4: Bajos (3 meses)', 'BAJA', 90)
            ]

            for phase_name, severity, days in timelines:
                findings = severity_groups[severity]
                if findings:
                    f.write(f"### {phase_name}\n\n")
                    f.write(f"**Hallazgos a remediar**: {len(findings)}\n")
                    f.write(f"**Tiempo estimado**: {days} días\n\n")

                    # Agrupar por código
                    by_code = {}
                    for finding in findings:
                        code = finding.get('id', 'UNKNOWN')
                        if code not in by_code:
                            by_code[code] = []
                        by_code[code].append(finding)

                    for code, code_findings in by_code.items():
                        f.write(
                            f"#### {code} ({len(code_findings)} ocurrencias)\n\n")

                        # Obtener recomendación única
                        recommendation = None
                        for finding in code_findings:
                            details = finding.get('details', {})
                            if isinstance(details, dict):
                                recommendation = details.get('recommendation')
                                if recommendation:
                                    break

                        if recommendation:
                            f.write(f"**Acción**: {recommendation}\n\n")

                        # Listar recursos afectados (máximo 5)
                        f.write("**Recursos afectados**:\n")
                        for finding in code_findings[:5]:
                            details = finding.get('details', {})
                            if isinstance(details, dict):
                                resource = details.get('vpc_name') or details.get('sg_name') or \
                                    details.get('resource_name') or 'N/A'
                                region = details.get('region', 'N/A')
                                f.write(f"- {resource} ({region})\n")

                        if len(code_findings) > 5:
                            f.write(
                                f"- *... y {len(code_findings) - 5} más*\n")

                        f.write("\n")

            # Estimación de esfuerzo
            f.write("## 📊 Estimación de Esfuerzo\n\n")

            total_hours = {
                'CRITICA': len(severity_groups['CRITICA']) * 4,
                'ALTA': len(severity_groups['ALTA']) * 3,
                'MEDIA': len(severity_groups['MEDIA']) * 2,
                'BAJA': len(severity_groups['BAJA']) * 1
            }

            f.write("| Severidad | Hallazgos | Horas/Hallazgo | Total Horas |\n")
            f.write("|-----------|-----------|----------------|-------------|\n")

            for severity in ['CRITICA', 'ALTA', 'MEDIA', 'BAJA']:
                count = len(severity_groups[severity])
                hours_per = {'CRITICA': 4, 'ALTA': 3,
                             'MEDIA': 2, 'BAJA': 1}[severity]
                total = total_hours[severity]
                f.write(f"| {severity} | {count} | {hours_per} | {total} |\n")

            f.write(
                f"\n**Total estimado**: {sum(total_hours.values())} horas\n\n")

            # Métricas de éxito
            f.write("## 🎯 Métricas de Éxito\n\n")
            f.write("- Score de seguridad objetivo: **80/100**\n")
            f.write("- Eliminar el 100% de hallazgos críticos\n")
            f.write("- Reducir hallazgos altos en un 80%\n")
            f.write("- Implementar monitoreo continuo para todos los recursos\n")
            f.write("- Documentar todas las excepciones de seguridad\n\n")

            f.write("---\n\n")
            f.write(
                "*Plan generado automáticamente - Requiere revisión del equipo de seguridad*\n")

        self.logger.info(f"Plan de remediación generado: {remediation_path}")
        return remediation_path

    def _generate_compliance_report(self, output_path: Path) -> Path:
        """Generar reporte de compliance con frameworks"""
        compliance_path = output_path / \
            f"network_compliance_{self.timestamp}.md"

        with open(compliance_path, 'w', encoding='utf-8') as f:
            f.write(f"# 📋 Reporte de Compliance de Red - {CLIENT_NAME}\n\n")
            f.write(f"**Fecha**: {datetime.now().strftime('%d/%m/%Y')}\n\n")

            # Mapear hallazgos a frameworks
            f.write("## Mapeo de Controles\n\n")

            f.write("| Código | Control | CIS | ISO 27001 | NIST CSF | Estado |\n")
            f.write("|--------|---------|-----|-----------|----------|--------|\n")

            # Verificar cada control NET
            findings_by_code = {}
            for finding in self._get_all_findings():
                code = finding.get('id', '')
                if code not in findings_by_code:
                    findings_by_code[code] = []
                findings_by_code[code].append(finding)

            control_descriptions = {
                'NET-001': 'VPC sin Segregación de Subnets',
                'NET-002': 'Subnets Públicas sin Justificación',
                'NET-003': 'Security Groups con Reglas Permisivas',
                'NET-004': 'Puertos Críticos Expuestos',
                'NET-005': 'Ausencia de Network ACLs',
                'NET-006': 'VPC Peering sin Restricciones',
                'NET-007': 'ELB sin Cifrado SSL/TLS',
                'NET-008': 'Ausencia de Flow Logs'
            }

            for code in ['NET-001', 'NET-002', 'NET-003', 'NET-004',
                         'NET-005', 'NET-006', 'NET-007', 'NET-008']:
                compliance = self.compliance_mapping.get(code, {})
                status = '❌ No Cumple' if code in findings_by_code else '✅ Cumple'

                f.write(
                    f"| {code} | {control_descriptions.get(code, 'N/A')} | ")
                f.write(f"{compliance.get('CIS', 'N/A')} | ")
                f.write(f"{compliance.get('ISO', 'N/A')} | ")
                f.write(f"{compliance.get('NIST', 'N/A')} | ")
                f.write(f"{status} |\n")

            # Resumen por framework
            f.write("\n## Resumen de Cumplimiento\n\n")

            total_controls = 8
            controls_failed = len(findings_by_code)
            compliance_percentage = (
                (total_controls - controls_failed) / total_controls * 100)

            f.write(f"- **Controles evaluados**: {total_controls}\n")
            f.write(
                f"- **Controles que cumplen**: {total_controls - controls_failed}\n")
            f.write(f"- **Controles que no cumplen**: {controls_failed}\n")
            f.write(
                f"- **Porcentaje de cumplimiento**: {compliance_percentage:.1f}%\n\n")

            f.write("---\n\n")
            f.write("*Reporte de compliance basado en controles de red evaluados*\n")

        self.logger.info(f"Reporte de compliance generado: {compliance_path}")
        return compliance_path

    def _get_risk_level(self, score: int) -> str:
        """Determinar nivel de riesgo basado en score"""
        if score >= 90:
            return "Excelente"
        elif score >= 75:
            return "Bueno"
        elif score >= 60:
            return "Regular"
        elif score >= 40:
            return "Deficiente"
        else:
            return "Crítico"
