# Assessment de Seguridad - Camuzzi Gas Pampeana S.A.

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

- **Recursos Analizados**: 37
- **Regiones Cubiertas**: 0
- **Servicios Evaluados**: 5

### Hallazgos Clave

| Severidad | Cantidad | Porcentaje |
|-----------|----------|------------|
| 🔴 CRITICAL | 1 | 1.6% |
| 🟠 HIGH | 58 | 93.5% |
| 🟡 MEDIUM | 3 | 4.8% |
| 🟢 LOW | 0 | 0.0% |

### Estado de Madurez

- **Score de Seguridad**: 50.65/100
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
- Usuarios sin MFA: 13
- Compliance MFA: 18.75%
- Access Keys antiguas: 0

**Hallazgos principales**:

- 🟠 **[IAM-002]** Usuario sin MFA habilitado: Christian Vazquez
- 🟠 **[IAM-002]** Usuario sin MFA habilitado: ConectorCloud
- 🟠 **[IAM-002]** Usuario sin MFA habilitado: dcabral
- 🟠 **[IAM-002]** Usuario sin MFA habilitado: diegogarone
- 🟠 **[IAM-002]** Usuario sin MFA habilitado: Florencia Pavon
- *(y 43 hallazgos más)*

### NETWORK

**Estadísticas**:

- Total VPCs: 9
- Security Groups: 7
- Recursos expuestos: 0
- Puertos críticos expuestos: 0

**Hallazgos principales**:

- 🟠 **[NET-002]** Subnet pública sin justificación: Subnet_DESA
- 🟠 **[NET-002]** Subnet pública sin justificación: Subnet_BACKUP
- 🟠 **[NET-002]** Subnet pública sin justificación: Subnet_QA
- 🟠 **[NET-002]** Subnet pública sin justificación: Subnet_KUBERNETES
- 🟠 **[NET-002]** Subnet pública sin justificación: Direct_Connect
- *(y 5 hallazgos más)*

### STORAGE

**Estadísticas**:

- Volúmenes EVS: 0
- Buckets OBS: 0
- Compliance de cifrado: 0%
- Buckets públicos: 0

**Hallazgos principales**:

- 🟡 **[STO-001]** Volumen EVS sin cifrar: VM-W19SOFTTEK01-volume-0001

### MONITORING

**Estadísticas**:

- Total de alarmas: 0
- Cloud Trace habilitado: No
- Retención promedio de logs: 0 días


## 4. Análisis de Cumplimiento

**Cumplimiento General**: 55.0%

### Cumplimiento por Framework

| Framework | Cumplimiento | Estado |
|-----------|--------------|--------|
| CIS_Huawei_Cloud_1.1 | 60.0% | ⚠️ Requiere Mejora |
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
| IAM-004 | 🟠 HIGH | iam | Access Key sin rotación por 764 días |
| IAM-004 | 🟠 HIGH | iam | Access Key sin rotación por 1918 días |
| IAM-004 | 🟠 HIGH | iam | Access Key sin rotación por 2211 días |
| IAM-004 | 🟠 HIGH | iam | Access Key sin rotación por 1214 días |
| IAM-004 | 🟠 HIGH | iam | Access Key sin rotación por 332 días |
| IAM-004 | 🟠 HIGH | iam | Access Key sin rotación por 2285 días |
| IAM-004 | 🟠 HIGH | iam | Access Key sin rotación por 2242 días |
| IAM-004 | 🟠 HIGH | iam | Access Key sin rotación por 678 días |
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
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación: Subnet_DESA |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación: Subnet_BACKUP |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación: Subnet_QA |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación: Subnet_KUBERNETES |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación: Direct_Connect |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación: Subnet_MGMT |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación: Subnet_PROD |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación: Internet |
| NET-002 | 🟠 HIGH | network | Subnet pública sin justificación: Subnet_Transit_Redes_Internas |
| NET-006 | 🟠 HIGH | network | Regla permite todo el tráfico desde Internet |
| COMP-002 | 🟠 HIGH | compliance | CIS 1.3 - 8 access keys sin rotar en 90+ días |
| IAM-005 | 🟡 MEDIUM | iam | Política de contraseñas débil: longitud mínima 6 |
| STO-001 | 🟡 MEDIUM | storage | Volumen EVS sin cifrar: VM-W19SOFTTEK01-volume-0001 |
| COMP-003 | 🟡 MEDIUM | compliance | CIS 1.4 - Política de contraseñas débil |
