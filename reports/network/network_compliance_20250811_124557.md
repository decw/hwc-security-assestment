# 📋 Reporte de Compliance de Red - CCGP S.A.

**Fecha**: 11/08/2025

## Mapeo de Controles

| Código | Control | CIS | ISO 27001 | NIST CSF | Estado |
|--------|---------|-----|-----------|----------|--------|
| NET-001 | VPC sin Segregación de Subnets | CIS 2.1 | ISO 27001 A.13.1.1 | NIST PR.AC-5 | ❌ No Cumple |
| NET-002 | Subnets Públicas sin Justificación | CIS 2.2 | ISO 27001 A.13.1.3 | NIST PR.AC-5 | ❌ No Cumple |
| NET-003 | Security Groups con Reglas 0.0.0.0/0 | CIS 4.1-4.4 | ISO 27001 A.13.1.1 | NIST PR.AC-5 | ❌ No Cumple |
| NET-004 | Puertos Críticos Expuestos a Internet | CIS 4.1-4.4 | ISO 27001 A.13.1.1 | NIST PR.AC-5 | ✅ Cumple |
| NET-005 | Ausencia de Network ACLs | CIS 3.1-3.7 | ISO 27001 A.13.1.1 | NIST PR.AC-5 | ❌ No Cumple |
| NET-006 | VPC Peering sin Restricciones | CIS 2.3 | ISO 27001 A.13.1.3 | NIST PR.AC-5 | ✅ Cumple |
| NET-007 | ELB sin Cifrado SSL/TLS | CIS 2.4 | ISO 27001 A.10.1.1 | NIST PR.DS-2 | ❌ No Cumple |
| NET-008 | Ausencia de Flow Logs | CIS 2.5 | ISO 27001 A.12.4.1 | NIST DE.CM-1 | ❌ No Cumple |
| NET-009 | Sin Aislamiento entre Ambientes | CIS 4.6 | ISO 27001 A.13.1.3 | NIST PR.AC-5 | ✅ Cumple |
| NET-010 | Comunicación Lateral sin Restricción | CIS 4.5 | ISO 27001 A.13.1.1 | NIST PR.AC-5 | ✅ Cumple |
| NET-011 | Sin Integración con Fortinet SIEM | N/A | ISO 27001 A.12.4.1 | NIST DE.AE-1 | ❌ No Cumple |
| NET-012 | EIPs sin Justificación Documentada | N/A | ISO 27001 A.8.1.1 | NIST ID.AM-2 | ✅ Cumple |
| NET-013 | Bandwidth sin Límites Configurados | N/A | ISO 27001 A.13.2.1 | NIST PR.DS-5 | ❌ No Cumple |
| NET-014 | Route Tables sin Documentación | N/A | ISO 27001 A.12.1.1 | NIST ID.AM-3 | ✅ Cumple |
| NET-015 | DNS Resolver sin Restricciones | CIS 2.6 | ISO 27001 A.13.1.1 | NIST PR.AC-5 | ❌ No Cumple |
| NET-016 | NAT Gateway sin Alta Disponibilidad | N/A | ISO 27001 A.17.1.1 | NIST PR.PT-5 | ❌ No Cumple |
| NET-017 | NAT Gateway Compartido entre Ambientes | N/A | ISO 27001 A.13.1.3 | NIST PR.AC-5 | ❌ No Cumple |
| NET-018 | Sin VPC Endpoints para Servicios | N/A | ISO 27001 A.13.1.1 | NIST PR.AC-5 | ❌ No Cumple |
| NET-019 | Cross-Region Traffic sin Cifrado | N/A | ISO 27001 A.10.1.1 | NIST PR.DS-2 | ❌ No Cumple |
| NET-020 | Sin Segmentación de Bases de Datos | CIS 4.6 | ISO 27001 A.13.1.3 | NIST PR.AC-5 | ✅ Cumple |

## Resumen de Cumplimiento

- **Controles evaluados**: 20
- **Controles que cumplen**: 2
- **Controles que no cumplen**: 18
- **Porcentaje de cumplimiento**: 10.0%

---

*Reporte de compliance basado en controles de red evaluados*
