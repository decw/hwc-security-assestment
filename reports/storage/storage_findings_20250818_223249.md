# 🔒 Reporte de Hallazgos - Dominio STORAGE

**Fecha**: 2025-08-18 22:32
**Cliente**: CAMUZZI GAS PAMPEANA S.A.
**Plataforma**: Huawei Cloud
**Alcance**: 251 EVS, 1 OBS, KMS, Backup Services

## 📊 Resumen Ejecutivo

Se identificaron **9 vulnerabilidades** en la configuración de almacenamiento:

| Severidad | Cantidad | Porcentaje |
|-----------|----------|------------|
| 🔴 CRITICAL | 0 | 0.0% |
| 🟠 HIGH | 0 | 0.0% |
| 🟡 MEDIUM | 0 | 0.0% |
| 🟢 LOW | 0 | 0.0% |

### 📈 Métricas de Seguridad

- **Cobertura de Cifrado**: 40.0%
- **Cobertura de Backup**: 30.0%
- **Volúmenes sin cifrar**: 12/251
- **Buckets públicos**: 0/1
- **KMS Keys sin rotación**: 4

## 🔍 Hallazgos Detallados

### 🔴 [STO-001] Volúmenes EVS sin Cifrado

**Severidad**: CRITICAL | **CVSS**: 8.6
**Recursos Afectados**: 12

**Descripción**:
Volúmenes de almacenamiento sin cifrado habilitado

**Evidencia**:
- unencrypted_volumes: 5 items encontrados
  - evs-la-santiago-***-001
  - evs-la-santiago-***-002
  - evs-la-santiago-***-004

**Recomendación**:
Habilitar cifrado en todos los volúmenes EVS, especialmente producción

**Compliance**: CIS: CIS 5.1 | ISO: ISO 27001 A.10.1.1 | NIST: NIST PR.DS-1

---

### 🟠 [STO-009] Backups No Configurados

**Severidad**: HIGH | **CVSS**: 7.5
**Recursos Afectados**: 10

**Descripción**:
Recursos sin políticas de backup automático configuradas

**Evidencia**:
- resources_without_backup: 5 items encontrados
  - evs-la-santiago-***-001
  - evs-la-santiago-***-002
  - evs-la-santiago-***-003

**Recomendación**:
Configurar CSBS/VBS para backups automáticos

**Compliance**: ISO: ISO 27001 A.12.3.1 | NIST: NIST PR.IP-4

---

### 🟡 [STO-003] Ausencia de Versionado en OBS

**Severidad**: MEDIUM | **CVSS**: 5.3
**Recursos Afectados**: 1

**Descripción**:
Buckets sin versionado habilitado para protección contra eliminación

**Evidencia**:
- buckets_without_versioning: 1 items encontrados
  - camuzzi-backup-***

**Recomendación**:
Habilitar versionado en buckets críticos

**Compliance**: CIS: CIS 5.3 | ISO: ISO 27001 A.12.3.1 | NIST: NIST PR.IP-4

---

### 🟢 [STO-004] Políticas de Lifecycle Ausentes

**Severidad**: LOW | **CVSS**: 3.1
**Recursos Afectados**: 1

**Descripción**:
Sin políticas de lifecycle para gestión de datos antiguos

**Evidencia**:
- buckets_without_lifecycle: 1 items encontrados
  - camuzzi-backup-***

**Recomendación**:
Configurar políticas de lifecycle para optimizar costos

**Compliance**: CIS: CIS 5.4 | ISO: ISO 27001 A.8.3.3 | NIST: NIST PR.DS-3

---

### 🟡 [STO-005] Access Logging Deshabilitado

**Severidad**: MEDIUM | **CVSS**: 4.3
**Recursos Afectados**: 1

**Descripción**:
Buckets sin logging de acceso habilitado

**Evidencia**:
- buckets_without_logging: 1 items encontrados
  - camuzzi-backup-***

**Recomendación**:
Habilitar logging de acceso en buckets OBS

**Compliance**: CIS: CIS 5.5 | ISO: ISO 27001 A.12.4.1 | NIST: NIST DE.AE-3

---

### 🟠 [STO-006] KMS Keys sin Rotación

**Severidad**: HIGH | **CVSS**: 7.1
**Recursos Afectados**: 4

**Descripción**:
Llaves de cifrado KMS sin política de rotación automática

**Evidencia**:
- keys_without_rotation: 4 items encontrados
  - kms-key-la-santiago-***-001
  - kms-key-la-santiago-***-002
  - kms-key-la-buenos aires1-***-001

**Recomendación**:
Configurar rotación automática de llaves KMS

**Compliance**: CIS: CIS 5.6 | ISO: ISO 27001 A.10.1.2 | NIST: NIST PR.DS-1

---

### 🟠 [STO-007] Snapshots sin Cifrado

**Severidad**: HIGH | **CVSS**: 7.5
**Recursos Afectados**: 2

**Descripción**:
Snapshots de volúmenes sin cifrado aplicado

**Evidencia**:
- unencrypted_snapshots: 2 items encontrados
  - snapshot-la-santiago-***-001
  - snapshot-la-buenos aires1-***-001

**Recomendación**:
Cifrar todos los snapshots de volúmenes

**Compliance**: CIS: CIS 5.7 | ISO: ISO 27001 A.10.1.1 | NIST: NIST PR.DS-1

---

### 🟡 [STO-008] Cross-Region Replication Ausente

**Severidad**: MEDIUM | **CVSS**: 5.9
**Recursos Afectados**: 1

**Descripción**:
Sin replicación cross-region para datos críticos

**Evidencia**:
- resources_without_replication: 1 items encontrados
  - camuzzi-backup-***

**Recomendación**:
Implementar replicación cross-region para datos críticos

**Compliance**: ISO: ISO 27001 A.17.1.2 | NIST: NIST PR.IP-4

---

### 🔴 [STO-010] Vaults de Backup sin Inmutabilidad

**Severidad**: CRITICAL | **CVSS**: 9.0
**Recursos Afectados**: 2

**Descripción**:
CBS/VBS vaults sin protección WORM contra ransomware

**Evidencia**:
- vaults_without_immutability: 2 items encontrados
  - vault-la-santiago-***-001
  - vault-la-buenos aires1-***-001

**Recomendación**:
Activar inmutabilidad (WORM) en todos los vaults de backup críticos

**Compliance**: CIS: CIS 5.8 | ISO: ISO 27001 A.12.3.1 | NIST: NIST PR.PT-5

---

## 🌍 Distribución Regional

| Región | EVS | OBS | KMS |
|--------|-----|-----|-----|
| LA-Santiago | 10 | 1 | 3 |
| LA-Buenos Aires1 | 10 | 0 | 3 |