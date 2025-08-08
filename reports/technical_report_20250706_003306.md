# Assessment de Seguridad - CCGP S.A.

**Fecha**: 06/07/2025
**Versión**: 1.0
**Clasificación**: CONFIDENCIAL

## Tabla de Contenidos

1. [Resumen Ejecutivo](#resumen-ejecutivo)
2. [Metodología](#metodología)
3. [Hallazgos por Módulo](#hallazgos-por-módulo)
4. [Análisis de Cumplimiento](#análisis-de-cumplimiento)
5. [Recomendaciones](#recomendaciones)
6. [Anexos](#anexos)

## 1. Resumen Ejecutivo

### Alcance del Assessment

- **Recursos Analizados**: 50
- **Regiones Cubiertas**: 0
- **Servicios Evaluados**: 5

### Hallazgos Clave

| Severidad | Cantidad | Porcentaje |
|-----------|----------|------------|
| 🔴 CRITICAL | 16 | 20.3% |
| 🟠 HIGH | 36 | 45.6% |
| 🟡 MEDIUM | 14 | 17.7% |
| 🟢 LOW | 13 | 16.5% |

### Estado de Madurez

- **Score de Seguridad**: 51.77/100
- **Nivel de Riesgo**: ALTO
- **Nivel de Madurez Actual**: 2.4/5.0
- **Nivel de Madurez Objetivo**: 3.0/5.0

## 2. Metodología

El assessment siguió los siguientes frameworks y estándares:

- CIS Benchmarks for Cloud Security v1.4.0
- NIST Cybersecurity Framework v2.0
- ISO 27001:2022
- Huawei Cloud Security Best Practices

## 3. Hallazgos por Módulo

### IAM

**Estadísticas**:

- Total de usuarios: 16
- Usuarios sin MFA: 0
- Compliance MFA: 100.0%
- Access Keys antiguas: 0

**Hallazgos principales**:

- 🔴 **[IAM-001]** Usuario con privilegios administrativos: ConectorCloud
- 🔴 **[IAM-001]** Usuario con privilegios administrativos: diegogarone
- 🔴 **[IAM-001]** Usuario con privilegios administrativos: emilianosilva
- 🔴 **[IAM-001]** Usuario con privilegios administrativos: Florencia Pavon
- 🔴 **[IAM-001]** Usuario con privilegios administrativos: globo
- *(y 20 hallazgos más)*

### NETWORK

**Estadísticas**:

- Total VPCs: 0
- Security Groups: 0
- Recursos expuestos: 0
- Puertos críticos expuestos: 0

**Hallazgos principales**:

- 🔴 **[NET-004]** Puertos críticos expuestos a Internet en LA-Santiago - SG «Sys-default» (0 instancias)
- 🔴 **[NET-004]** Puertos críticos expuestos a Internet en LA-Santiago - SG «Sys-default» (0 instancias)
- 🔴 **[NET-004]** Puertos críticos expuestos a Internet en CN-Hong Kong - SG «default» (0 instancias)
- 🔴 **[NET-004]** Puertos críticos expuestos a Internet en CN-Hong Kong - SG «default» (0 instancias)
- 🟠 **[NET-002]** Subnet pública sin justificación en LA-Santiago: Subnet_QA
- *(y 42 hallazgos más)*

### STORAGE

**Estadísticas**:

- Volúmenes EVS: 0
- Buckets OBS: 0
- Compliance de cifrado: 0%
- Buckets públicos: 0

**Hallazgos principales**:

- 🟠 **[STO-009]** No se encontraron backups configurados en región la-south-2
- 🟠 **[STO-009]** No se encontraron backups configurados en región sa-argentina-1
- 🟠 **[STO-009]** No se encontraron backups configurados en región ap-southeast-1
- 🟠 **[STO-009]** No se encontraron backups configurados en región ap-southeast-3
- 🟠 **[STO-009]** No se encontraron backups configurados en región ap-southeast-2

### MONITORING

**Estadísticas**:

- Total de alarmas: 0
- Cloud Trace habilitado: No
- Retención promedio de logs: 0 días


## 4. Análisis de Cumplimiento

**Cumplimiento General**: 60.0%

### Cumplimiento por Framework

| Framework | Cumplimiento | Estado |
|-----------|--------------|--------|
| CIS_Huawei_Cloud_1.1 | 70.0% | ⚠️ Requiere Mejora |
| ISO_27001_2022 | 50.0% | ❌ Crítico |
| NIST_CSF_2.0 | 0% | ❌ Crítico |

## 5. Recomendaciones

### 🔴 Prioridad Crítica

**Remediar: CIS 2.1 - Cloud Trace Service no configurado**
- Finding COMP-004 requiere atención inmediata
- Impacto: Muy Alto
- Esfuerzo: Variable

### 🟠 Prioridad Alta

**Implementar programa de seguridad formal**
- Establecer políticas, procedimientos y responsabilidades

**Automatizar controles de seguridad**
- Implementar Infrastructure as Code y políticas automatizadas


## 6. Anexos

### A. Detalle de Hallazgos

| ID | Severidad | Módulo | Descripción |
|----|-----------|--------|-------------|
| IAM-001 | 🔴 CRITICAL | iam | Usuario con privilegios administrativos: ConectorCloud |
| IAM-001 | 🔴 CRITICAL | iam | Usuario con privilegios administrativos: diegogarone |
| IAM-001 | 🔴 CRITICAL | iam | Usuario con privilegios administrativos: emilianosilva |
| IAM-001 | 🔴 CRITICAL | iam | Usuario con privilegios administrativos: Florencia Pavon |
| IAM-001 | 🔴 CRITICAL | iam | Usuario con privilegios administrativos: globo |
| IAM-001 | 🔴 CRITICAL | iam | Usuario con privilegios administrativos: Julian Vazzano |
| IAM-001 | 🔴 CRITICAL | iam | Usuario con privilegios administrativos: Nicolas Alcorta |
| IAM-001 | 🔴 CRITICAL | iam | Usuario con privilegios administrativos: Nicolas Villafane |
| IAM-001 | 🔴 CRITICAL | iam | Usuario con privilegios administrativos: SManoni |
| IAM-001 | 🔴 CRITICAL | iam | Usuario con privilegios administrativos: us_gustavo-dpetrasso-acamuzzigas-dcom-d... |
| IAM-001 | 🔴 CRITICAL | iam | Usuario con privilegios administrativos: VeeamBackup_Huawei |
| NET-004 | 🔴 CRITICAL | network | Puertos críticos expuestos a Internet en LA-Santiago - SG «Sys-default» (0 insta... |
| NET-004 | 🔴 CRITICAL | network | Puertos críticos expuestos a Internet en LA-Santiago - SG «Sys-default» (0 insta... |
| NET-004 | 🔴 CRITICAL | network | Puertos críticos expuestos a Internet en CN-Hong Kong - SG «default» (0 instanci... |
| NET-004 | 🔴 CRITICAL | network | Puertos críticos expuestos a Internet en CN-Hong Kong - SG «default» (0 instanci... |
| COMP-004 | 🔴 CRITICAL | compliance | CIS 2.1 - Cloud Trace Service no configurado |
| IAM-013 | 🟠 HIGH | iam | Contraseñas sin expiración configurada |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Santiago: Subnet_QA |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Santiago: Subnet_MGMT |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Santiago: subnet-t2 |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Santiago: subnet-t1 |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Santiago: Subnet_KUBERNETES |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Santiago: subnet-t3 |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Santiago: Subnet_RedesInternas |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Santiago: Subnet_PROD |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Santiago: Subnet_Internet |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Santiago: Subnet_DESA |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Santiago: Subnet_BACKUP |
| NET-006 | 🟠 HIGH | network | Regla permite TODO el tráfico desde Internet en LA-Santiago - SG «sg-Forti-LAN» ... |
| NET-006 | 🟠 HIGH | network | Regla permite TODO el tráfico desde Internet en LA-Santiago - SG «sg-Forti-LAN» ... |
| NET-006 | 🟠 HIGH | network | Regla permite TODO el tráfico desde Internet en LA-Santiago - SG «sg-Forti-WAN» ... |
| NET-006 | 🟠 HIGH | network | Regla permite TODO el tráfico desde Internet en LA-Santiago - SG «sg-Forti-WAN» ... |
| NET-006 | 🟠 HIGH | network | Regla permite TODO el tráfico desde Internet en LA-Santiago - SG «sg-Permit-ALL»... |
| NET-006 | 🟠 HIGH | network | Regla permite TODO el tráfico desde Internet en LA-Santiago - SG «sg-Permit-ALL»... |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Buenos Aires1: Subnet_DESA |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Buenos Aires1: Subnet_BACKUP |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Buenos Aires1: Subnet_QA |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Buenos Aires1: Subnet_KUBERNETES |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Buenos Aires1: Direct_Connect |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Buenos Aires1: Subnet_MGMT |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Buenos Aires1: Subnet_PROD |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Buenos Aires1: Internet |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Buenos Aires1: Subnet_Transit_Redes_Inter... |
| NET-006 | 🟠 HIGH | network | Regla permite TODO el tráfico desde Internet en LA-Buenos Aires1 - SG «sg-Permit... |
| NET-006 | 🟠 HIGH | network | Regla permite TODO el tráfico desde Internet en CN-Hong Kong - SG «Sys-FullAcces... |
| NET-006 | 🟠 HIGH | network | Regla permite TODO el tráfico desde Internet en CN-Hong Kong - SG «Sys-WebServer... |
| NET-REGIONAL-001 | 🟠 HIGH | network | Alta concentración de recursos en una región: 85.6% en Buenos Aires |
| STO-009 | 🟠 HIGH | storage | No se encontraron backups configurados en región la-south-2 |
| STO-009 | 🟠 HIGH | storage | No se encontraron backups configurados en región sa-argentina-1 |
| STO-009 | 🟠 HIGH | storage | No se encontraron backups configurados en región ap-southeast-1 |
| STO-009 | 🟠 HIGH | storage | No se encontraron backups configurados en región ap-southeast-3 |
| STO-009 | 🟠 HIGH | storage | No se encontraron backups configurados en región ap-southeast-2 |
| IAM-005 | 🟡 MEDIUM | iam | Política de contraseñas débil: longitud mínima 6 |
| IAM-008 | 🟡 MEDIUM | iam | Política de contraseñas requiere solo 2 tipos de caracteres |
| IAM-022 | 🟡 MEDIUM | iam | 11 usuarios administrativos sin límites de permisos |
| IAM-023 | 🟡 MEDIUM | iam | Agency con acceso desde dominio externo: cbc_partneragent_hwc83871270 |
| IAM-023 | 🟡 MEDIUM | iam | Agency con acceso desde dominio externo: cce_admin_trust |
| IAM-023 | 🟡 MEDIUM | iam | Agency con acceso desde dominio externo: CESAgentAutoConfigAgency |
| IAM-023 | 🟡 MEDIUM | iam | Agency con acceso desde dominio externo: cts_admin_trust |
| IAM-023 | 🟡 MEDIUM | iam | Agency con acceso desde dominio externo: PrendeApagaAgency |
| IAM-023 | 🟡 MEDIUM | iam | Agency con acceso desde dominio externo: prueba |
| IAM-023 | 🟡 MEDIUM | iam | Agency con acceso desde dominio externo: ssa_admin_trust |
| NET-INV-AP- | 🟡 MEDIUM | network | No se pudo analizar 4 recursos en AP-Bangkok |
| NET-INV-AP- | 🟡 MEDIUM | network | No se pudo analizar 2 recursos en AP-Singapore |
| NET-CONSOLIDATION-001 | 🟡 MEDIUM | network | Arquitectura multi-VPC compleja: 19 VPCs en 5 regiones |
| COMP-003 | 🟡 MEDIUM | compliance | CIS 1.4 - Política de contraseñas débil |
| IAM-015 | 🟢 LOW | iam | Historial de contraseñas insuficiente: 1 |
| IAM-016 | 🟢 LOW | iam | Sin edad mínima de contraseña configurada |
| IAM-017 | 🟢 LOW | iam | Permite muchos caracteres idénticos consecutivos: 0 |
| NET-005 | 🟢 LOW | network | Elastic IP sin utilizar en LA-Buenos Aires1: 119.8.77.23 |
| NET-005 | 🟢 LOW | network | Elastic IP sin utilizar en LA-Buenos Aires1: 119.8.73.37 |
| NET-005 | 🟢 LOW | network | Elastic IP sin utilizar en LA-Buenos Aires1: 119.8.73.10 |
| NET-005 | 🟢 LOW | network | Elastic IP sin utilizar en LA-Buenos Aires1: 119.8.76.197 |
| NET-005 | 🟢 LOW | network | Elastic IP sin utilizar en LA-Buenos Aires1: 119.8.78.94 |
| NET-005 | 🟢 LOW | network | Elastic IP sin utilizar en LA-Buenos Aires1: 119.8.78.160 |
| NET-005 | 🟢 LOW | network | Elastic IP sin utilizar en LA-Buenos Aires1: 119.8.72.196 |
| NET-005 | 🟢 LOW | network | Elastic IP sin utilizar en LA-Buenos Aires1: 119.8.77.68 |
| NET-005 | 🟢 LOW | network | Elastic IP sin utilizar en LA-Buenos Aires1: 119.8.77.27 |
| NET-SPRAWL-001 | 🟢 LOW | network | Recursos dispersos en regiones con pocos servicios |
