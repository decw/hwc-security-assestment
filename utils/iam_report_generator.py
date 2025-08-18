#!/usr/bin/env python3
"""
Generador de reportes específico para IAM
Genera JSON y resumen detallado con secciones
"""

import json
import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import pandas as pd

from config.settings import REPORTS_DIR, CLIENT_NAME, REPORT_TIMESTAMP
from utils.logger import SecurityLogger


class IAMReportGenerator:
    """Generador de reportes IAM con resumen detallado"""

    def __init__(self, iam_results: Dict[str, Any]):
        self.results = iam_results
        self.timestamp = REPORT_TIMESTAMP
        self.logger = SecurityLogger('IAMReportGenerator')

    # --------------------------------------------------------------------- #
    # Helpers                                                                #
    # --------------------------------------------------------------------- #
    def _get_all_findings(self) -> List[Dict[str, Any]]:
        """
        Combina los hallazgos del collector y las vulnerabilidades
        del analizador en una lista común unificada.
        """
        findings = self.results.get('findings', []).copy()

        # Convertir vulnerabilidades a formato de finding estándar
        for vuln in self.results.get('vulnerabilities', []):
            findings.append(
                {
                    "id": vuln.get("id", ""),
                    "severity": vuln.get("severity", "LOW").upper(),
                    "message": vuln.get("title", ""),
                    "details": vuln.get("description", ""),
                    "timestamp": vuln.get("discovered_date", ""),
                }
            )
        return findings

    def generate_complete_report(self, output_dir: str = None) -> Dict[str, str]:
        """Generar reporte completo: JSON + Resumen detallado"""
        # Siempre usar reports/iam/ como base
        iam_reports_dir = REPORTS_DIR / 'iam'

        # Si se proporciona output_dir, asegurarse de que sea subdirectorio de reports/iam/
        if output_dir:
            output_path = Path(output_dir)
            if not str(output_path).startswith(str(REPORTS_DIR)):
                # Si el directorio proporcionado está fuera de reports/, usar reports/iam/
                output_path = iam_reports_dir
        else:
            output_path = iam_reports_dir

        # Asegurar que el directorio existe
        output_path.mkdir(parents=True, exist_ok=True)

        results = {}

        # Generar reportes con manejo de errores individual
        try:
            json_path = self._generate_json_report(output_path)
            results['json'] = str(json_path)
            self.logger.info(f"✅ JSON generado: {json_path}")
        except Exception as e:
            self.logger.error(f"❌ Error generando JSON: {e}")
            results['json'] = None

        try:
            summary_path = self._generate_detailed_summary(output_path)
            results['summary'] = str(summary_path)
            self.logger.info(f"✅ Summary generado: {summary_path}")
        except Exception as e:
            self.logger.error(f"❌ Error generando summary: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            results['summary'] = None

        try:
            csv_path = self._generate_findings_csv(output_path)
            results['csv'] = str(csv_path)
            self.logger.info(f"✅ CSV generado: {csv_path}")
        except Exception as e:
            self.logger.error(f"❌ Error generando CSV: {e}")
            results['csv'] = None

        try:
            remediation_path = self._generate_remediation_plan(output_path)
            results['remediation'] = str(remediation_path)
            self.logger.info(
                f"✅ Plan de remediación generado: {remediation_path}")
        except Exception as e:
            self.logger.error(f"❌ Error generando plan de remediación: {e}")
            results['remediation'] = None

        return results

    def _generate_json_report(self, output_path: Path) -> Path:
        """Generar reporte JSON completo"""
        json_path = output_path / f"iam_assessment_{self.timestamp}.json"

        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2,
                      ensure_ascii=False, default=str)

        self.logger.info(f"Reporte JSON generado: {json_path}")
        return json_path

    def _generate_detailed_summary(self, output_path: Path) -> Path:
        """Generar resumen detallado con secciones (dinámicas)"""
        summary_path = output_path / f"iam_summary_{self.timestamp}.md"

        # Determinar presencia de inventario
        has_users = len(self.results.get('users', [])) > 0
        has_groups = len(self.results.get('groups', [])) > 0
        has_roles = len(self.results.get('roles', [])) > 0
        has_pols = len(self.results.get('policies', [])) > 0
        has_keys = len(self.results.get('access_keys', [])) > 0

        # Construir TOC dinámico
        toc_lines = ["## 📋 Tabla de Contenidos",
                     "",
                     "1. [Resumen Ejecutivo](#resumen-ejecutivo)"]

        section_writers = []

        if has_users:
            toc_lines.append(
                f"{len(toc_lines)}. [Análisis de Usuarios](#análisis-de-usuarios)")
            section_writers.append(self._generate_users_section)

        if has_groups:
            toc_lines.append(
                f"{len(toc_lines)}. [Análisis de Grupos](#análisis-de-grupos)")
            section_writers.append(self._generate_groups_section)

        if has_roles:       # solo si realmente hay roles
            toc_lines.append(
                f"{len(toc_lines)}. [Análisis de Roles](#análisis-de-roles)")
            section_writers.append(self._generate_roles_section)

        if has_pols:
            toc_lines.append(
                f"{len(toc_lines)}. [Análisis de Políticas](#análisis-de-políticas)")
            section_writers.append(self._generate_policies_section)

        # Secciones siempre presentes
        toc_lines.extend([
            f"{len(toc_lines)}. [Estado de MFA](#estado-de-mfa)",
            f"{len(toc_lines)+1}. [Hallazgos de Seguridad](#hallazgos-de-seguridad)",
            f"{len(toc_lines)+2}. [Estadísticas Generales](#estadísticas-generales)",
            f"{len(toc_lines)+3}. [Recomendaciones](#recomendaciones)",
            f"{len(toc_lines)+4}. [Anexos](#anexos)",
            "---",
            ""
        ])

        try:
            with open(summary_path, 'w', encoding='utf-8') as f:
                # Header
                try:
                    f.write(self._generate_header())
                    self.logger.debug("✅ Header escrito")
                except Exception as e:
                    self.logger.error(f"❌ Error en header: {e}")
                    raise

                # TOC dinámico
                try:
                    f.write("\n".join(toc_lines))
                    self.logger.debug("✅ TOC escrito")
                except Exception as e:
                    self.logger.error(f"❌ Error en TOC: {e}")
                    raise

                # Resumen ejecutivo
                try:
                    exec_summary = self._generate_executive_summary()
                    f.write(exec_summary)
                    self.logger.debug(
                        f"✅ Resumen ejecutivo escrito ({len(exec_summary)} chars)")
                except Exception as e:
                    self.logger.error(f"❌ Error en resumen ejecutivo: {e}")
                    import traceback
                    self.logger.error(f"Traceback: {traceback.format_exc()}")
                    # Escribir mensaje de error en lugar de fallar completamente
                    f.write(
                        "\n## 🎯 Resumen Ejecutivo\n\n❌ **Error generando resumen ejecutivo**\n\n")

                # Secciones de inventario (solo si hay datos)
                for i, writer in enumerate(section_writers):
                    try:
                        section_content = writer()
                        f.write(section_content)
                        self.logger.debug(
                            f"✅ Sección {i+1} escrita ({len(section_content)} chars)")
                    except Exception as e:
                        self.logger.error(f"❌ Error en sección {i+1}: {e}")
                        f.write(f"\n## ❌ Error en Sección {i+1}\n\n")

                # MFA (siempre relevante)
                try:
                    mfa_content = self._generate_mfa_section()
                    f.write(mfa_content)
                    self.logger.debug(
                        f"✅ Sección MFA escrita ({len(mfa_content)} chars)")
                except Exception as e:
                    self.logger.error(f"❌ Error en sección MFA: {e}")
                    f.write(
                        "\n## 🔐 Estado de MFA\n\n❌ **Error generando sección MFA**\n\n")

                # Access Keys solo si existen
                if has_keys:
                    try:
                        keys_content = self._generate_access_keys_section()
                        f.write(keys_content)
                        self.logger.debug(
                            f"✅ Sección Access Keys escrita ({len(keys_content)} chars)")
                    except Exception as e:
                        self.logger.error(
                            f"❌ Error en sección Access Keys: {e}")
                        f.write(
                            "\n## 🔑 Análisis de Access Keys\n\n❌ **Error generando sección Access Keys**\n\n")

                # Hallazgos + estadísticas + recomendaciones + anexos
                sections = [
                    ("Security Findings", self._generate_security_findings_section),
                    ("Statistics", self._generate_statistics_section),
                    ("Recommendations", self._generate_recommendations_section),
                    ("Annexes", self._generate_annexes)
                ]

                for section_name, section_func in sections:
                    try:
                        section_content = section_func()
                        f.write(section_content)
                        self.logger.debug(
                            f"✅ Sección {section_name} escrita ({len(section_content)} chars)")
                    except Exception as e:
                        self.logger.error(
                            f"❌ Error en sección {section_name}: {e}")
                        f.write(f"\n## ❌ Error en {section_name}\n\n")

            self.logger.info(f"Resumen detallado generado: {summary_path}")

            # Verificar que el archivo se escribió correctamente
            if summary_path.exists():
                file_size = summary_path.stat().st_size
                self.logger.info(f"Archivo generado: {file_size} bytes")
                if file_size < 1000:
                    self.logger.warning(
                        f"⚠️ Archivo muy pequeño: {file_size} bytes")

            return summary_path

        except Exception as e:
            self.logger.error(f"❌ Error crítico generando summary: {e}")
            import traceback
            self.logger.error(f"Traceback completo: {traceback.format_exc()}")
            raise

    def _generate_header(self) -> str:
        """Generar header del reporte"""
        return f"""# Assessment de Seguridad IAM - {CLIENT_NAME}

**Fecha de Assessment**: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}  
**Versión del Reporte**: 1.0  
**Clasificación**: CONFIDENCIAL  
**Generado por**: Huawei Cloud Security Assessment Tool  

---

"""

    # La función previa _generate_toc está obsoleta y se mantiene sólo por compatibilidad,
    # pero ahora ya no se llama directamente.

    def _generate_executive_summary(self) -> str:
        """Generar resumen ejecutivo"""
        stats = self.results.get('statistics', {})
        findings = self._get_all_findings()

        # Contar hallazgos por severidad
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in findings:
            severity = finding.get('severity', 'LOW')
            severity_counts[severity] += 1

        total_findings = len(findings)
        total_users = stats.get('total_users', 0)
        mfa_compliance = stats.get('mfa_compliance_rate', 0)

        content = f"""## 🎯 Resumen Ejecutivo

### 📊 Métricas Clave

| Métrica | Valor |
|---------|-------|
| **Total de Usuarios** | {total_users} |
| **Usuarios sin MFA** | {stats.get('users_without_mfa', 0)} |
| **Tasa de Cumplimiento MFA** | {mfa_compliance:.1f}% |
| **Access Keys Antiguas** | {stats.get('old_access_keys', 0)} |
| **Usuarios Inactivos** | {stats.get('inactive_users', 0)} |
| **Cuentas de Servicio** | {stats.get('service_accounts', 0)} |

### 🚨 Hallazgos de Seguridad

| Severidad | Cantidad | Porcentaje |
|-----------|----------|------------|
| 🔴 CRÍTICO | {severity_counts['CRITICAL']} | {(severity_counts['CRITICAL']/total_findings*100) if total_findings > 0 else 0:.1f}% |
| 🟠 ALTO | {severity_counts['HIGH']} | {(severity_counts['HIGH']/total_findings*100) if total_findings > 0 else 0:.1f}% |
| 🟡 MEDIO | {severity_counts['MEDIUM']} | {(severity_counts['MEDIUM']/total_findings*100) if total_findings > 0 else 0:.1f}% |
| 🟢 BAJO | {severity_counts['LOW']} | {(severity_counts['LOW']/total_findings*100) if total_findings > 0 else 0:.1f}% |

### ⚠️ Principales Riesgos Identificados

"""

        # Agregar los 5 hallazgos más críticos
        critical_findings = [f for f in findings if f.get('severity') in [
            'CRITICAL', 'HIGH']]
        critical_findings = sorted(critical_findings, key=lambda x: x.get(
            'severity') == 'CRITICAL', reverse=True)[:5]

        for i, finding in enumerate(critical_findings, 1):
            severity_icon = "🔴" if finding.get(
                'severity') == 'CRITICAL' else "🟠"
            content += f"{severity_icon} **{i}. {finding.get('message', 'Sin descripción')}**\n"
            content += f"   - ID: {finding.get('id', 'N/A')}\n"

            # CORREGIDO: Manejar detalles de forma segura para evitar problemas de formato
            details = finding.get('details', {})
            if isinstance(details, dict) and details:
                # Mostrar solo información clave de los detalles
                if 'user_name' in details:
                    content += f"   - Usuario: {details.get('user_name', 'N/A')}\n"
                if 'count' in details:
                    content += f"   - Cantidad: {details.get('count', 'N/A')}\n"
                if 'recommendation' in details:
                    content += f"   - Recomendación: {details.get('recommendation', 'N/A')}\n"
                # Agregar más campos según sea necesario
            elif details:
                # Si no es diccionario, mostrar como string truncado
                content += f"   - Detalles: {str(details)[:100]}...\n"
            content += "\n"

        content += "---\n\n"
        return content

    def _generate_users_section(self) -> str:
        """Generar sección de análisis de usuarios"""
        users = self.results.get('users', [])
        stats = self.results.get('statistics', {})

        content = f"""## 👥 Análisis de Usuarios

###  Resumen General

- **Total de Usuarios**: {len(users)}
- **Usuarios Habilitados**: {sum(1 for u in users if u.get('enabled', True))}
- **Usuarios Deshabilitados**: {sum(1 for u in users if not u.get('enabled', True))}
- **Usuarios Inactivos**: {stats.get('inactive_users', 0)}
- **Cuentas de Servicio**: {stats.get('service_accounts', 0)}

### 🔍 Detalle de Usuarios

| Usuario | Estado | Último Login | MFA | Grupos | Acceso Admin |
|---------|--------|--------------|-----|--------|--------------|
"""

        for user in users[:10]:  # Mostrar solo los primeros 10
            username = user.get('name', 'N/A')
            enabled = "✅" if user.get('enabled', True) else "❌"
            last_login = user.get('last_login_time', 'Nunca')[
                :10] if user.get('last_login_time') else 'Nunca'
            mfa_status = "✅" if user.get('id') not in [u.get('user_id') for u in self.results.get(
                'mfa_status', {}).get('users_without_mfa', [])] else "❌"
            groups = len(self.results.get(
                'user_group_mappings', {}).get(user.get('id'), []))
            admin_access = "" if user.get('id') in [u.get(
                'user_id') for u in self.results.get('privileged_accounts', [])] else "✅"

            content += f"| {username} | {enabled} | {last_login} | {mfa_status} | {groups} | {admin_access} |\n"

        if len(users) > 10:
            content += f"| ... y {len(users) - 10} usuarios más | | | | | |\n"

        content += "\n### 🚨 Usuarios Críticos\n\n"

        # Usuarios sin MFA
        users_without_mfa = self.results.get(
            'mfa_status', {}).get('users_without_mfa', [])
        if users_without_mfa:
            content += "**Usuarios sin MFA:**\n"
            for user in users_without_mfa[:5]:
                content += f"- {user.get('user_name', 'N/A')}\n"
            if len(users_without_mfa) > 5:
                content += f"- ... y {len(users_without_mfa) - 5} usuarios más\n"
            content += "\n"

        # Usuarios privilegiados
        privileged_users = self.results.get('privileged_accounts', [])
        if privileged_users:
            content += "**Usuarios con Privilegios Administrativos:**\n"
            for user in privileged_users[:5]:
                content += f"- {user.get('user_name', 'N/A')} (fuente: {user.get('privilege_source', 'N/A')})\n"
            if len(privileged_users) > 5:
                content += f"- ... y {len(privileged_users) - 5} usuarios más\n"
            content += "\n"

        content += "---\n\n"
        return content

    def _generate_groups_section(self) -> str:
        """Generar sección de análisis de grupos"""
        groups = self.results.get('groups', [])

        content = f"""##  Análisis de Grupos

###  Resumen General

- **Total de Grupos**: {len(groups)}
- **Grupos con Miembros**: {sum(1 for g in groups if g.get('member_count', 0) > 0)}
- **Grupos Vacíos**: {sum(1 for g in groups if g.get('member_count', 0) == 0)}

### 🔍 Detalle de Grupos

| Grupo | Miembros | Descripción |
|-------|----------|-------------|
"""

        for group in groups:
            name = group.get('name', 'N/A')
            members = group.get('member_count', 0)
            description = group.get('description', 'Sin descripción')[:50]

            content += f"| {name} | {members} | {description} |\n"

        content += "\n### 🚨 Grupos Críticos\n\n"

        # Grupos administrativos
        admin_groups = [g for g in groups if any(keyword in g.get('name', '').lower()
                                                 for keyword in ['admin', 'administrator', 'power'])]
        if admin_groups:
            content += "**Grupos Administrativos:**\n"
            for group in admin_groups:
                content += f"- {group.get('name', 'N/A')} ({group.get('member_count', 0)} miembros)\n"
            content += "\n"

        # Grupos vacíos
        empty_groups = [g for g in groups if g.get('member_count', 0) == 0]
        if empty_groups:
            content += "**Grupos Vacíos (posible limpieza):**\n"
            for group in empty_groups[:5]:
                content += f"- {group.get('name', 'N/A')}\n"
            if len(empty_groups) > 5:
                content += f"- ... y {len(empty_groups) - 5} grupos más\n"
            content += "\n"

        content += "---\n\n"
        return content

    def _generate_roles_section(self) -> str:
        """Generar sección de análisis de roles"""
        roles = self.results.get('roles', [])

        content = f"""## 🎭 Análisis de Roles

###  Resumen General

- **Total de Roles**: {len(roles)}
- **Roles del Sistema**: {sum(1 for r in roles if r.get('type') == 'system')}
- **Roles Personalizados**: {sum(1 for r in roles if r.get('type') == 'custom')}

###  Detalle de Roles

| Rol | Tipo | Descripción | Referencias |
|-----|------|-------------|-------------|
"""

        for role in roles:
            name = role.get('name', 'N/A')
            role_type = role.get('type', 'N/A')
            description = role.get('description', 'Sin descripción')[:50]
            references = role.get('references', 0)

            content += f"| {name} | {role_type} | {description} | {references} |\n"

        content += "\n###  Roles Críticos\n\n"

        # Roles con permisos excesivos
        excessive_roles = [r for r in roles if r.get('policy') and
                           any(pattern in str(r.get('policy'))
                               for pattern in ['*:*:*', '"Action": ["*"]'])]
        if excessive_roles:
            content += "**Roles con Permisos Excesivos:**\n"
            for role in excessive_roles:
                content += f"- {role.get('name', 'N/A')} ({role.get('type', 'N/A')})\n"
            content += "\n"

        content += "---\n\n"
        return content

    def _generate_policies_section(self) -> str:
        """Generar sección de análisis de políticas"""
        policies = self.results.get('policies', [])
        password_policy = self.results.get('password_policy', {})
        login_policy = self.results.get('login_policy', {})

        content = f"""## 📋 Análisis de Políticas

### 📑 Políticas IAM
        
**Total de Políticas IAM**: {len(policies)}

"""

        # Separar por tipo
        custom_policies = [p for p in policies if p.get('type') == 'custom']
        system_policies = [p for p in policies if p.get('type') == 'system']

        if custom_policies:
            content += f"\n#### Políticas Personalizadas ({len(custom_policies)})\n\n"
            content += "| Nombre | Descripción | Referencias | Creada |\n"
            content += "|--------|-------------|-------------|--------|\n"

            for policy in custom_policies[:10]:
                name = policy.get('name', 'N/A')
                description = (policy.get('description', 'Sin descripción')[:40] + '...') if len(
                    policy.get('description', '')) > 40 else policy.get('description', 'Sin descripción')
                references = policy.get('references', 0)
                created = policy.get(
                    'created_at', 'N/A')[:10] if policy.get('created_at') else 'N/A'

                content += f"| {name} | {description} | {references} | {created} |\n"

            if len(custom_policies) > 10:
                content += f"| ... y {len(custom_policies) - 10} políticas más | | | |\n"

        if system_policies:
            content += f"\n#### Políticas del Sistema ({len(system_policies)})\n\n"
            content += "| Nombre | Tipo | Descripción |\n"
            content += "|--------|------|-------------|\n"

            for policy in system_policies[:10]:
                name = policy.get('name', 'N/A')
                p_type = policy.get('type', 'system')
                description = (policy.get('description', 'Sin descripción')[:50] + '...') if len(
                    policy.get('description', '')) > 50 else policy.get('description', 'Sin descripción')

                content += f"| {name} | {p_type} | {description} |\n"

            if len(system_policies) > 10:
                content += f"| ... y {len(system_policies) - 10} políticas más | | |\n"

        # Si no hay políticas, mostrar mensaje informativo
        if len(policies) == 0:
            content += """
⚠️ **No se encontraron políticas IAM personalizadas**

Esto puede indicar que:
- No hay políticas personalizadas creadas en la cuenta
- El usuario no tiene permisos para listar políticas
- La API de políticas no está disponible en esta región

Las políticas predefinidas del sistema están implícitas en los roles asignados.
"""

        content += f"""
### 🔐 Política de Contraseñas

| Configuración | Valor Actual | Recomendado | Estado |
|---------------|--------------|-------------|--------|
| Longitud Mínima | {password_policy.get('minimum_password_length', 'N/A')} | 12 | {'✅' if password_policy.get('minimum_password_length', 0) >= 12 else '❌'} |
| Complejidad | {password_policy.get('password_char_combination', 'N/A')} tipos | 3+ tipos | {'✅' if password_policy.get('password_char_combination', 0) >= 3 else '❌'} |
| Expiración | {password_policy.get('password_validity_period', 'N/A')} días | 90 días | {'✅' if 0 < password_policy.get('password_validity_period', 0) <= 90 else '❌'} |
| Historial | {password_policy.get('number_of_recent_passwords_disallowed', 'N/A')} | 5 | {'✅' if password_policy.get('number_of_recent_passwords_disallowed', 0) >= 5 else '❌'} |

### 🔒 Política de Login

| Configuración | Valor Actual | Recomendado | Estado |
|---------------|--------------|-------------|--------|
| Intentos Fallidos | {login_policy.get('login_failed_times', 'N/A')} | 5 | {'✅' if 0 < login_policy.get('login_failed_times', 0) <= 5 else '❌'} |
| Bloqueo | {login_policy.get('lockout_duration', 'N/A')} minutos | 30 min | {'✅' if login_policy.get('lockout_duration', 0) >= 30 else '❌'} |
| Timeout Sesión | {login_policy.get('session_timeout', 'N/A')} minutos | 480 min | {'✅' if 0 < login_policy.get('session_timeout', 0) <= 480 else '❌'} |

---

"""
        return content

    def _generate_mfa_section(self) -> str:
        """Generar sección de análisis de MFA con nuevas categorías"""
        mfa_status = self.results.get('mfa_status', {})
        verification_summary = mfa_status.get('verification_summary', {})

        content = f"""## 🔐 Estado de MFA y Verificación de Acceso

### 📊 Resumen General

- **Total de Usuarios con Acceso a Consola**: {verification_summary.get('total_console_users', 0)}
- **MFA Real Habilitado**: {mfa_status.get('mfa_enabled', 0)} ({verification_summary.get('real_mfa_percentage', 0)}%)
- **Verificación 2FA Habilitada**: {verification_summary.get('verification_2fa_count', 0)} ({verification_summary.get('verification_2fa_percentage', 0)}%)
- **Sin Verificación**: {verification_summary.get('no_verification_count', 0)} ({verification_summary.get('no_verification_percentage', 0)}%)

### 🛡️ MFA Real (Autenticación Multifactor Verdadera)

| Método | Usuarios | Porcentaje |
|--------|----------|------------|
| Virtual MFA Device | {mfa_status.get('mfa_types', {}).get('virtual', 0)} | {round((mfa_status.get('mfa_types', {}).get('virtual', 0) / verification_summary.get('total_console_users', 1)) * 100, 1)}% |
| Security Key | {mfa_status.get('mfa_types', {}).get('security_key', 0)} | {round((mfa_status.get('mfa_types', {}).get('security_key', 0) / verification_summary.get('total_console_users', 1)) * 100, 1)}% |

### 📱 Verificación 2FA (Métodos de Verificación)

| Método | Usuarios | Porcentaje |
|--------|----------|------------|
| 2FA SMS | {mfa_status.get('verification_methods', {}).get('sms', 0)} | {round((mfa_status.get('verification_methods', {}).get('sms', 0) / verification_summary.get('total_console_users', 1)) * 100, 1)}% |
| 2FA Email | {mfa_status.get('verification_methods', {}).get('email', 0)} | {round((mfa_status.get('verification_methods', {}).get('email', 0) / verification_summary.get('total_console_users', 1)) * 100, 1)}% |
| Virtual MFA (VMFA) | {mfa_status.get('verification_methods', {}).get('vmfa', 0)} | {round((mfa_status.get('verification_methods', {}).get('vmfa', 0) / verification_summary.get('total_console_users', 1)) * 100, 1)}% |

### ⚠️ Sin Verificación

| Estado | Usuarios | Porcentaje |
|--------|----------|------------|
| Disabled | {mfa_status.get('verification_methods', {}).get('disabled', 0)} | {verification_summary.get('no_verification_percentage', 0)}% |

### 📈 Distribución Detallada por Usuario

"""

        # Tabla de usuarios por método
        users_by_method = {}
        for user_detail in mfa_status.get('login_verification_details', []):
            if user_detail['has_console_access']:
                method = user_detail['login_verification_method']
                if method not in users_by_method:
                    users_by_method[method] = []
                users_by_method[method].append(user_detail)

        for method, users in users_by_method.items():
            if users:
                content += f"\n#### {method} ({len(users)} usuarios)\n\n"
                content += "| Usuario | Tipo de Cuenta | Access Mode |\n"
                content += "|---------|----------------|-------------|\n"

                for user in users[:10]:  # Limitar a 10 usuarios por método
                    account_type = "🔧 Servicio" if user['is_service_account'] else "👤 Regular"
                    content += f"| {user['user_name']} | {account_type} | {user['access_mode']} |\n"

                if len(users) > 10:
                    content += f"| ... y {len(users) - 10} usuarios más | | |\n"

        content += "\n---\n\n"
        return content

    def _generate_access_keys_section(self) -> str:
        """Generar sección de análisis de access keys"""
        access_keys = self.results.get('access_keys', [])
        stats = self.results.get('statistics', {})

        content = f"""##  Análisis de Access Keys

###  Resumen General

- **Total de Access Keys**: {len(access_keys)}
- **Keys Activas**: {sum(1 for k in access_keys if k.get('status') == 'active')}
- **Keys Inactivas**: {sum(1 for k in access_keys if k.get('status') != 'active')}
- **Keys Antiguas (>90 días)**: {stats.get('old_access_keys', 0)}
- **Keys Sin Uso**: {stats.get('unused_access_keys', 0)}

### 🔍 Detalle de Access Keys

| Usuario | Estado | Edad (días) | Último Uso | Servicio |
|---------|--------|-------------|------------|----------|
"""

        for key in access_keys[:10]:  # Mostrar solo las primeras 10
            user_name = key.get('user_name', 'N/A')
            status = "✅" if key.get('status') == 'active' else "❌"
            age = key.get('age_days', 0)
            last_used = key.get('last_used_service', 'Nunca')
            service = key.get('last_used_service', 'N/A')

            content += f"| {user_name} | {status} | {age} | {last_used} | {service} |\n"

        if len(access_keys) > 10:
            content += f"| ... y {len(access_keys) - 10} keys más | | | | |\n"

        content += "\n### 🚨 Access Keys Críticas\n\n"

        # Keys antiguas
        old_keys = [k for k in access_keys if k.get(
            'age_days', 0) > 90 and k.get('status') == 'active']
        if old_keys:
            content += "**Access Keys Antiguas (>90 días):**\n"
            for key in old_keys[:5]:
                content += f"- {key.get('user_name', 'N/A')} ({key.get('age_days', 0)} días)\n"
            if len(old_keys) > 5:
                content += f"- ... y {len(old_keys) - 5} keys más\n"
            content += "\n"

        # Keys sin uso
        unused_keys = [k for k in access_keys if not k.get(
            'last_used') and k.get('age_days', 0) > 30]
        if unused_keys:
            content += "**Access Keys Sin Uso (>30 días):**\n"
            for key in unused_keys[:5]:
                content += f"- {key.get('user_name', 'N/A')} ({key.get('age_days', 0)} días)\n"
            if len(unused_keys) > 5:
                content += f"- ... y {len(unused_keys) - 5} keys más\n"
            content += "\n"

        content += "---\n\n"
        return content

    def _generate_security_findings_section(self) -> str:
        """Generar sección de hallazgos de seguridad"""
        # Obtener findings del collector
        findings = self.results.get('findings', [])

        # Obtener vulnerabilidades del análisis
        vulnerabilities = self.results.get('vulnerabilities', [])

        content = f"""## 🚨 Hallazgos de Seguridad

### 📊 Resumen de Hallazgos

- **Total de Hallazgos del Collector**: {len(findings)}
- **Total de Vulnerabilidades del Análisis**: {len(vulnerabilities)}
"""

        # Mostrar findings del collector
        if findings:
            content += "\n#### 🔍 Findings del Collector\n\n"
            # Agrupar por severidad
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            severity_icons = {'CRITICAL': '🔴',
                              'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': ''}

            for severity in severity_order:
                severity_findings = [
                    f for f in findings if f.get('severity') == severity]
                if severity_findings:
                    content += f"#### {severity_icons[severity]} {severity}\n\n"

                    for finding in severity_findings:
                        content += f"**{finding.get('id', 'N/A')}**: {finding.get('message', 'Sin descripción')}\n"
                        details = finding.get('details', {})
                        if details:
                            content += f"- Detalles: {details}\n"
                        content += f"- Timestamp: {finding.get('timestamp', 'N/A')}\n\n"

        # Mostrar vulnerabilidades del análisis
        if vulnerabilities:
            content += "\n#### 🚨 Vulnerabilidades Identificadas\n\n"
            for vuln in vulnerabilities:
                content += f"**{vuln.get('title', 'Sin título')}**\n"
                content += f"- Severidad: {vuln.get('severity', 'N/A')}\n"
                content += f"- Tipo: {vuln.get('type', 'N/A')}\n"
                content += f"- Descripción: {vuln.get('description', 'Sin descripción')}\n\n"

        content += "---\n\n"
        return content

    def _generate_statistics_section(self) -> str:
        """Generar sección de estadísticas"""
        stats = self.results.get('statistics', {})

        content = f"""##  Estadísticas Generales

### 👥 Usuarios

| Métrica | Valor |
|---------|-------|
| Total de Usuarios | {stats.get('total_users', 0)} |
| Usuarios sin MFA | {stats.get('users_without_mfa', 0)} |
| Tasa de Cumplimiento MFA | {stats.get('mfa_compliance_rate', 0):.1f}% |
| Usuarios Inactivos | {stats.get('inactive_users', 0)} |
| Cuentas de Servicio | {stats.get('service_accounts', 0)} |
| Usuarios Privilegiados | {stats.get('privileged_accounts', 0)} |

###  Access Keys

| Métrica | Valor |
|---------|-------|
| Total de Access Keys | {stats.get('total_access_keys', 0)} |
| Keys Antiguas (>90 días) | {stats.get('old_access_keys', 0)} |
| Keys Sin Uso | {stats.get('unused_access_keys', 0)} |

### 🎭 Roles y Políticas

| Métrica | Valor |
|---------|-------|
| Total de Roles | {stats.get('total_roles', 0)} |
| Total de Políticas | {stats.get('total_policies', 0)} |
| Total de Grupos | {stats.get('total_groups', 0)} |

### 🚨 Hallazgos por Severidad

| Severidad | Cantidad |
|-----------|----------|
| CRÍTICO | {stats.get('findings_by_severity', {}).get('CRITICAL', 0)} |
| ALTO | {stats.get('findings_by_severity', {}).get('HIGH', 0)} |
| MEDIO | {stats.get('findings_by_severity', {}).get('MEDIUM', 0)} |
| BAJO | {stats.get('findings_by_severity', {}).get('LOW', 0)} |

---

"""
        return content

    def _generate_recommendations_section(self) -> str:
        """Generar sección de recomendaciones"""
        findings = self._get_all_findings()

        content = """## 💡 Recomendaciones

### 🚨 Acciones Críticas (Inmediatas)

"""

        critical_findings = [
            f for f in findings if f.get('severity') == 'CRITICAL']
        if critical_findings:
            for finding in critical_findings:
                content += f"1. **{finding.get('message', 'Sin descripción')}**\n"
                content += f"   - ID: {finding.get('id', 'N/A')}\n"
                content += f"   - Acción: Implementar inmediatamente\n\n"
        else:
            content += "✅ No hay hallazgos críticos que requieran acción inmediata.\n\n"

        content += "### 🔧 Acciones de Alto Impacto (1-2 semanas)\n\n"

        high_findings = [f for f in findings if f.get('severity') == 'HIGH']
        if high_findings:
            for finding in high_findings[:5]:  # Top 5
                content += f"1. **{finding.get('message', 'Sin descripción')}**\n"
                content += f"   - ID: {finding.get('id', 'N/A')}\n"
                content += f"   - Acción: Planificar e implementar\n\n"
        else:
            content += "✅ No hay hallazgos de alto impacto pendientes.\n\n"

        content += "### 📈 Mejoras de Seguridad (1 mes)\n\n"

        medium_findings = [
            f for f in findings if f.get('severity') == 'MEDIUM']
        if medium_findings:
            for finding in medium_findings[:3]:  # Top 3
                content += f"1. **{finding.get('message', 'Sin descripción')}**\n"
                content += f"   - ID: {finding.get('id', 'N/A')}\n"
                content += f"   - Acción: Evaluar e implementar\n\n"
        else:
            content += "✅ No hay mejoras de seguridad pendientes.\n\n"

        content += "### 🎯 Mejores Prácticas Recomendadas\n\n"

        content += """1. **Implementar MFA para todos los usuarios**
   - Configurar MFA obligatorio
   - Usar aplicaciones autenticadoras

2. **Rotar Access Keys regularmente**
   - Establecer política de rotación cada 90 días
   - Eliminar keys no utilizadas

3. **Revisar permisos de usuarios**
   - Implementar principio de menor privilegio
   - Auditar permisos regularmente

4. **Fortalecer políticas de contraseñas**
   - Longitud mínima de 12 caracteres
   - Requerir complejidad adecuada

5. **Monitorear actividad de usuarios**
   - Implementar logging centralizado
   - Revisar logs regularmente

---

"""
        return content

    def _generate_annexes(self) -> str:
        """Generar anexos"""
        return """## 📎 Anexos

### A. Configuración Técnica

- **Herramienta**: Huawei Cloud Security Assessment Tool
- **Versión**: 1.0
- **Fecha de Assessment**: """ + datetime.now().strftime('%d/%m/%Y %H:%M:%S') + """
- **Alcance**: Análisis completo de configuración IAM

### B. Metodología

El assessment siguió las mejores prácticas de:
- CIS Benchmarks for Cloud Security
- NIST Cybersecurity Framework
- ISO 27001:2022
- Huawei Cloud Security Best Practices

### C. Contacto

Para consultas sobre este reporte, contactar al equipo de seguridad.

---

*Reporte generado automáticamente por Huawei Cloud Security Assessment Tool*
"""

    def _generate_findings_csv(self, output_path: Path) -> Path:
        """Generar CSV de hallazgos"""
        csv_path = output_path / f"iam_findings_{self.timestamp}.csv"

        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(
                ['ID', 'Severidad', 'Mensaje', 'Detalles', 'Timestamp'])

            for finding in self._get_all_findings():
                writer.writerow([
                    finding.get('id', ''),
                    finding.get('severity', ''),
                    finding.get('message', ''),
                    str(finding.get('details', '')),
                    finding.get('timestamp', '')
                ])

        self.logger.info(f"CSV de hallazgos generado: {csv_path}")
        return csv_path

    def _generate_remediation_plan(self, output_path: Path) -> Path:
        """Generar plan de remediación"""
        remediation_path = output_path / \
            f"iam_remediation_plan_{self.timestamp}.md"

        with open(remediation_path, 'w', encoding='utf-8') as f:
            f.write(f"# Plan de Remediación IAM - {CLIENT_NAME}\n\n")
            f.write(f"**Fecha**: {datetime.now().strftime('%d/%m/%Y')}\n\n")

            # Agrupar hallazgos por severidad
            severity_groups = {}
            for finding in self._get_all_findings():
                severity = finding.get('severity', 'LOW').upper()
                if severity not in severity_groups:
                    severity_groups[severity] = []
                severity_groups[severity].append(finding)

            # Generar plan por severidad
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            severity_titles = {
                'CRITICAL': 'Críticos (Inmediatos)',
                'HIGH': 'Altos (1-2 semanas)',
                'MEDIUM': 'Medios (1 mes)',
                'LOW': 'Bajos (3 meses)'
            }

            for severity in severity_order:
                if severity in severity_groups:
                    f.write(f"## {severity_titles[severity]}\n\n")

                    for finding in severity_groups[severity]:
                        f.write(
                            f"### {finding.get('id', 'N/A')}: {finding.get('message', 'Sin descripción')}\n\n")
                        f.write(
                            f"**Descripción**: {finding.get('message', 'Sin descripción')}\n\n")
                        f.write(
                            f"**Detalles**: {finding.get('details', {})}\n\n")
                        f.write(
                            f"**Acción Requerida**: [Pendiente de definir]\n\n")
                        f.write(f"**Responsable**: [Pendiente de asignar]\n\n")
                        f.write(
                            f"**Fecha Objetivo**: [Pendiente de definir]\n\n")
                        f.write("---\n\n")

        self.logger.info(f"Plan de remediación generado: {remediation_path}")
        return remediation_path
