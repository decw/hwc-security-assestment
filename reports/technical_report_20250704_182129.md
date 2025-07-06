# Assessment de Seguridad - CCGP S.A.

**Fecha**: 04/07/2025
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
| 🔴 CRITICAL | 5 | 7.9% |
| 🟠 HIGH | 43 | 68.3% |
| 🟡 MEDIUM | 5 | 7.9% |
| 🟢 LOW | 10 | 15.9% |

### Estado de Madurez

- **Score de Seguridad**: 54.76/100
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
- Compliance MFA: 0.0%
- Access Keys antiguas: 0

**Hallazgos principales**:

- 🟠 **[IAM-002]** Usuario sin MFA habilitado: Christian Vazquez
- 🟠 **[IAM-002]** Usuario sin MFA habilitado: ConectorCloud
- 🟠 **[IAM-002]** Usuario sin MFA habilitado: dcabral
- 🟠 **[IAM-002]** Usuario sin MFA habilitado: diegogarone
- 🟠 **[IAM-002]** Usuario sin MFA habilitado: Florencia Pavon
- *(y 9 hallazgos más)*

### NETWORK

**Estadísticas**:

- Total VPCs: 0
- Security Groups: 0
- Recursos expuestos: 0
- Puertos críticos expuestos: 0

**Hallazgos principales**:

- 🔴 **[NET-004]** Puertos críticos expuestos a Internet en LA-Santiago
- 🔴 **[NET-004]** Puertos críticos expuestos a Internet en LA-Santiago
- 🔴 **[NET-004]** Puertos críticos expuestos a Internet en CN-Hong Kong
- 🔴 **[NET-004]** Puertos críticos expuestos a Internet en CN-Hong Kong
- 🟠 **[NET-002]** Subnet pública sin justificación en LA-Santiago: Subnet_QA
- *(y 42 hallazgos más)*

### STORAGE

**Estadísticas**:

- Volúmenes EVS: 0
- Buckets OBS: 0
- Compliance de cifrado: 0%
- Buckets públicos: 0


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
| NET-004 | 🔴 CRITICAL | network | Puertos críticos expuestos a Internet en LA-Santiago |
| NET-004 | 🔴 CRITICAL | network | Puertos críticos expuestos a Internet en LA-Santiago |
| NET-004 | 🔴 CRITICAL | network | Puertos críticos expuestos a Internet en CN-Hong Kong |
| NET-004 | 🔴 CRITICAL | network | Puertos críticos expuestos a Internet en CN-Hong Kong |
| COMP-004 | 🔴 CRITICAL | compliance | CIS 2.1 - Cloud Trace Service no configurado |
| IAM-002 | 🟠 HIGH | iam | Usuario sin MFA habilitado: Christian Vazquez |
| IAM-002 | 🟠 HIGH | iam | Usuario sin MFA habilitado: ConectorCloud |
| IAM-002 | 🟠 HIGH | iam | Usuario sin MFA habilitado: dcabral |
| IAM-002 | 🟠 HIGH | iam | Usuario sin MFA habilitado: diegogarone |
| IAM-002 | 🟠 HIGH | iam | Usuario sin MFA habilitado: Florencia Pavon |
| IAM-002 | 🟠 HIGH | iam | Usuario sin MFA habilitado: globo |
| IAM-002 | 🟠 HIGH | iam | Usuario sin MFA habilitado: Julian Vazzano |
| IAM-002 | 🟠 HIGH | iam | Usuario sin MFA habilitado: Nicolas Alcorta |
| IAM-002 | 🟠 HIGH | iam | Usuario sin MFA habilitado: prueba.iis |
| IAM-002 | 🟠 HIGH | iam | Usuario sin MFA habilitado: Ricardo Huberman |
| IAM-002 | 🟠 HIGH | iam | Usuario sin MFA habilitado: rsuarez |
| IAM-002 | 🟠 HIGH | iam | Usuario sin MFA habilitado: SManoni |
| IAM-002 | 🟠 HIGH | iam | Usuario sin MFA habilitado: VeeamBackup_Huawei |
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
| NET-006 | 🟠 HIGH | network | Regla permite todo el tráfico desde Internet en LA-Santiago |
| NET-006 | 🟠 HIGH | network | Regla permite todo el tráfico desde Internet en LA-Santiago |
| NET-006 | 🟠 HIGH | network | Regla permite todo el tráfico desde Internet en LA-Santiago |
| NET-006 | 🟠 HIGH | network | Regla permite todo el tráfico desde Internet en LA-Santiago |
| NET-006 | 🟠 HIGH | network | Regla permite todo el tráfico desde Internet en LA-Santiago |
| NET-006 | 🟠 HIGH | network | Regla permite todo el tráfico desde Internet en LA-Santiago |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Buenos Aires1: Subnet_DESA |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Buenos Aires1: Subnet_BACKUP |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Buenos Aires1: Subnet_QA |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Buenos Aires1: Subnet_KUBERNETES |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Buenos Aires1: Direct_Connect |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Buenos Aires1: Subnet_MGMT |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Buenos Aires1: Subnet_PROD |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Buenos Aires1: Internet |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación en LA-Buenos Aires1: Subnet_Transit_Redes_Inter... |
| NET-006 | 🟠 HIGH | network | Regla permite todo el tráfico desde Internet en LA-Buenos Aires1 |
| NET-006 | 🟠 HIGH | network | Regla permite todo el tráfico desde Internet en CN-Hong Kong |
| NET-006 | 🟠 HIGH | network | Regla permite todo el tráfico desde Internet en CN-Hong Kong |
| NET-REGIONAL-001 | 🟠 HIGH | network | Alta concentración de recursos en una región: 85.6% en Buenos Aires |
| IAM-005 | 🟡 MEDIUM | iam | Política de contraseñas débil: longitud mínima 6 |
| NET-INV-AP- | 🟡 MEDIUM | network | No se pudo analizar 4 recursos en AP-Bangkok |
| NET-INV-AP- | 🟡 MEDIUM | network | No se pudo analizar 2 recursos en AP-Singapore |
| NET-CONSOLIDATION-001 | 🟡 MEDIUM | network | Arquitectura multi-VPC compleja: 19 VPCs en 5 regiones |
| COMP-003 | 🟡 MEDIUM | compliance | CIS 1.4 - Política de contraseñas débil |
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
