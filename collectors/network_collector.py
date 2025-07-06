#!/usr/bin/env python3
"""
Colector de configuraciones de red para Huawei Cloud - Multi-región
"""

import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
import ipaddress
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkcore.region.region import Region
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkvpc.v2 import *
from huaweicloudsdkecs.v2 import *

# Import para EIP
try:
    from huaweicloudsdkeip.v2 import *
    EIP_SDK_AVAILABLE = True
except ImportError:
    EIP_SDK_AVAILABLE = False
    print("WARNING: SDK de EIP no disponible. Instale con: pip install huaweicloudsdkeip")

from utils.logger import SecurityLogger
from config.settings import (
    HUAWEI_ACCESS_KEY, HUAWEI_SECRET_KEY,
    HUAWEI_PROJECT_ID, REGIONS, REGION_PROJECT_MAPPING
)
from config.constants import CRITICAL_PORTS

class NetworkCollector:
    """Colector de configuraciones de seguridad de red"""
    
    def __init__(self):
        self.logger = SecurityLogger('NetworkCollector')
        self.findings = []
        self.credentials = BasicCredentials(
            HUAWEI_ACCESS_KEY,
            HUAWEI_SECRET_KEY,
            HUAWEI_PROJECT_ID
        )
        
        # Mapeo de regiones del inventario a regiones SDK
        self.region_map = {
            'LA-Santiago': 'la-south-2',
            'LA-Buenos Aires1': 'sa-argentina-1',
            'CN-Hong Kong': 'ap-southeast-1',
            'AP-Bangkok': 'ap-southeast-2',
            'AP-Singapore': 'ap-southeast-3'
        }
        
        # Recursos por región según inventario
        self.inventory_by_region = {
            'LA-Santiago': {'resources': 50, 'ecs': 9, 'evs': 21, 'vpcs': 9, 'eips': 1},
            'LA-Buenos Aires1': {'resources': 369, 'ecs': 103, 'evs': 230, 'vpcs': 9, 'eips': 9},
            'CN-Hong Kong': {'resources': 6, 'vpcs': 1, 'function_graph': 2},
            'AP-Bangkok': {'resources': 4, 'function_graph': 3},
            'AP-Singapore': {'resources': 2, 'function_graph': 1}
        }
        
    def _get_vpc_client(self, region_alias: str):
        region_id  = self.region_map.get(region_alias, region_alias)      # la-south-2
        project_id = REGION_PROJECT_MAPPING[region_id]                        # mapa nuevo

        creds = BasicCredentials(HUAWEI_ACCESS_KEY,
                                HUAWEI_SECRET_KEY,
                                project_id)

        region_obj = Region(region_id, f"https://vpc.{region_id}.myhuaweicloud.com")

        return VpcClient.new_builder()\
            .with_credentials(creds)\
            .with_region(region_obj)\
            .build()
    
    def _get_ecs_client(self, region_alias: str) -> Optional[EcsClient]:
        """Devuelve un ECS client configurado para la región indicada."""
        actual_region = self.region_map.get(region_alias, region_alias)

        # 1. Project ID correcto
        try:
            project_id = REGION_PROJECT_MAPPING[actual_region]
        except KeyError:
            logger.error(f"No tengo Project-ID para la región {actual_region}")
            return None

        # 2. Credenciales por región
        creds = BasicCredentials(
            HUAWEI_ACCESS_KEY,
            HUAWEI_SECRET_KEY,
            project_id
        )

        # 3. Endpoint (puedes crear un pequeño helper)
        endpoint = f"https://ecs.{actual_region}.myhuaweicloud.com"
        region_obj = Region(actual_region, endpoint)

        # 4. Construye el cliente
        try:
            return (
                EcsClient.new_builder()
                .with_credentials(creds)
                .with_region(region_obj)
                .build()
            )
        except Exception as e:
            logger.error(f"Error creando cliente ECS para {actual_region}: {e}")
            return None
    
    def _get_eip_client(self, region: str) -> Optional[Any]:
        """Obtener cliente EIP para una región"""
        if not EIP_SDK_AVAILABLE:
            return None
            
        try:
            actual_region = self.region_map.get(region, region)
            endpoint = f"https://vpc.{actual_region}.myhuaweicloud.com"
            region_obj = Region(actual_region, endpoint)
            
            return EipClient.new_builder() \
                .with_credentials(self.credentials) \
                .with_region(region_obj) \
                .build()
                
        except Exception as e:
            self.logger.error(f"Error creando cliente EIP para {region}: {str(e)}")
            return None
    
    async def collect_all(self) -> Dict[str, Any]:
        """Recolectar todos los datos de red"""
        self.logger.info("Iniciando recolección de datos de red multi-región")
        
        results = {
            'vpcs': {},
            'subnets': {},
            'security_groups': {},
            'network_acls': {},
            'elastic_ips': {},
            'exposed_resources': [],
            'findings': self.findings,
            'statistics': {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Procesar TODAS las regiones con recursos
        all_regions = list(self.inventory_by_region.keys())
        
        for region in all_regions:
            region_info = self.inventory_by_region[region]
            self.logger.info(f"Analizando región: {region} ({region_info['resources']} recursos)")
            
            # Intentar obtener datos reales de la región
            try:
                # Solo intentar si hay recursos relevantes
                if region_info.get('vpcs', 0) > 0 or region_info.get('ecs', 0) > 0:
                    # VPCs
                    vpc_result = await self._collect_vpcs_safe(region)
                    if vpc_result:
                        results['vpcs'][region] = vpc_result
                    
                    # Subnets
                    subnet_result = await self._collect_subnets_safe(region)
                    if subnet_result:
                        results['subnets'][region] = subnet_result
                    
                    # Security Groups
                    sg_result = await self._collect_security_groups_safe(region)
                    if sg_result:
                        results['security_groups'][region] = sg_result
                    
                    # EIPs
                    if region_info.get('eips', 0) > 0:
                        eip_result = await self._collect_elastic_ips_with_sdk(region)
                        if eip_result:
                            results['elastic_ips'][region] = eip_result
                    
                    # Recursos expuestos
                    if region_info.get('ecs', 0) > 0:
                        exposed = await self._analyze_exposed_resources_safe(region)
                        if exposed:
                            results['exposed_resources'].extend(exposed)
                
                # Si no pudimos obtener datos reales, agregar hallazgo basado en inventario
                if region not in results['vpcs'] and region_info['resources'] > 0:
                    self._add_inventory_based_finding(region, region_info)
                    
            except exceptions.ClientRequestException as e:
                if "401" in str(e) or "403" in str(e):
                    self.logger.warning(f"Sin autorización para región {region}")
                    self._add_inventory_based_finding(region, region_info)
                else:
                    self.logger.error(f"Error en región {region}: {str(e)}")
            except Exception as e:
                self.logger.error(f"Error inesperado en región {region}: {str(e)}")
                self._add_inventory_based_finding(region, region_info)
        
        # Agregar análisis consolidado
        self._add_consolidated_findings(results)
        
        # Calcular estadísticas
        results['statistics'] = self._calculate_statistics(results)
        
        self.logger.info(f"Recolección de red completada. Hallazgos: {len(self.findings)}")
        return results
    
    async def _collect_vpcs_safe(self, region: str) -> Optional[List[Dict]]:
        """Recolectar VPCs con manejo de errores"""
        try:
            client = self._get_vpc_client(region)
            if not client:
                return None
                
            request = ListVpcsRequest()
            request.limit = 100
            response = client.list_vpcs(request)
            
            vpcs = []
            for vpc in response.vpcs:
                vpc_info = {
                    'id': vpc.id,
                    'name': vpc.name,
                    'cidr': vpc.cidr,
                    'status': vpc.status,
                    'description': getattr(vpc, 'description', ''),
                    'created_at': getattr(vpc, 'created_at', None)
                }
                
                # Verificar configuración
                if self._check_vpc_issues(vpc):
                    self._add_finding(
                        'NET-001',
                        'MEDIUM',
                        f'VPC con CIDR muy grande en {region}: {vpc.name}',
                        {
                            'vpc_id': vpc.id, 
                            'region': region, 
                            'cidr': vpc.cidr,
                            'hosts': str(ipaddress.ip_network(vpc.cidr).num_addresses)
                        }
                    )
                
                vpcs.append(vpc_info)
            
            self.logger.info(f"Recolectadas {len(vpcs)} VPCs en {region}")
            return vpcs
            
        except Exception as e:
            self.logger.error(f"Error recolectando VPCs en {region}: {str(e)}")
            return None
    
    async def _collect_subnets_safe(self, region: str) -> Optional[List[Dict]]:
        """Recolectar subnets con manejo de errores"""
        try:
            client = self._get_vpc_client(region)
            if not client:
                return None
                
            request = ListSubnetsRequest()
            request.limit = 100
            response = client.list_subnets(request)
            
            subnets = []
            public_count = 0
            
            for subnet in response.subnets:
                subnet_info = {
                    'id': subnet.id,
                    'name': subnet.name,
                    'cidr': subnet.cidr,
                    'vpc_id': subnet.vpc_id,
                    'gateway_ip': subnet.gateway_ip,
                    'availability_zone': getattr(subnet, 'availability_zone', None)
                }
                
                # Verificar subnet pública
                if self._is_public_subnet(subnet):
                    public_count += 1
                    if not self._requires_public_access(subnet):
                        self._add_finding(
                            'NET-002',
                            'HIGH',
                            f'Subnet pública sin justificación en {region}: {subnet.name}',
                            {
                                'subnet_id': subnet.id, 
                                'cidr': subnet.cidr, 
                                'region': region,
                                'gateway_ip': subnet.gateway_ip
                            }
                        )
                
                subnets.append(subnet_info)
            
            self.logger.info(f"Recolectadas {len(subnets)} subnets en {region} ({public_count} públicas)")
            return subnets
            
        except Exception as e:
            self.logger.error(f"Error recolectando subnets en {region}: {str(e)}")
            return None



    def _count_sg_assignments(self, sg_id: str, region: str) -> int:
        """
        Devuelve cuántas instancias / NIC usan este Security Group.
        Hace una sola pasada sobre ListServersDetails y filtra por sg.id.
        """
        try:
            client = self._get_ecs_client(region)
            if not client:
                return 0

            req  = ListServersDetailsRequest(limit=1000)
            resp = client.list_servers_details(req)

            attached = 0
            for srv in resp.servers:
                for sg in getattr(srv, 'security_groups', []):
                    sg_match = sg.id if hasattr(sg, "id") else sg.get("id")
                    if sg_match == sg_id:
                        attached += 1
                        break
            return attached
        except Exception:
            return 0


    async def _collect_security_groups_safe(self, region: str) -> Optional[List[Dict]]:
        """Recolectar security groups con manejo de errores"""
        try:
            client = self._get_vpc_client(region)
            if not client:
                return None
                
            request = ListSecurityGroupsRequest()
            request.limit = 100
            response = client.list_security_groups(request)
            
            security_groups = []
            overly_permissive = 0
            
            for sg in response.security_groups:
                sg_info = {
                    'id': sg.id,
                    'name': sg.name,
                    'description': getattr(sg, 'description', ''),
                    'rules_count': 0,
                    'critical_exposures': [],
                    'assigned_instances': 0
                }
                
                # Obtener reglas
                try:
                    attached = self._count_sg_assignments(sg.id, region)
                    sg_info["assigned_instances"] = attached

                    rules_request = ListSecurityGroupRulesRequest()
                    rules_request.security_group_id = sg.id
                    rules_response = client.list_security_group_rules(rules_request)
                    
                    sg_info['rules_count'] = len(rules_response.security_group_rules)
                    
                    for rule in rules_response.security_group_rules:
                        if self._is_dangerous_rule(rule):
                            overly_permissive += 1
                            self._analyze_security_group_rule(rule, sg.name, region, attached)
                            
                            # Agregar a exposiciones críticas
                            if self._is_critical_exposure(rule):
                                sg_info['critical_exposures'].append({
                                    'ports': f"{getattr(rule, 'port_range_min', 'any')}-{getattr(rule, 'port_range_max', 'any')}",
                                    'source': getattr(rule, 'remote_ip_prefix', 'any')
                                })
                            
                except Exception as e:
                    self.logger.debug(f"Error obteniendo reglas para SG {sg.id}: {str(e)}")
                
                security_groups.append(sg_info)
            
            self.logger.info(f"Recolectados {len(security_groups)} SGs en {region} ({overly_permissive} reglas peligrosas)")
            return security_groups
            
        except Exception as e:
            self.logger.error(f"Error recolectando security groups en {region}: {str(e)}")
            return None
    
    async def _collect_elastic_ips_with_sdk(self, region: str) -> Optional[List[Dict]]:
        """Recolectar EIPs usando el SDK dedicado"""
        if not EIP_SDK_AVAILABLE:
            self.logger.warning(f"SDK de EIP no disponible para {region}")
            return None
            
        try:
            client = self._get_eip_client(region)
            if not client:
                return None
                
            # Usar el SDK de EIP correcto
            request = ListPublicipsRequest()
            response = client.list_publicips(request)
            
            eips = []
            unused_count = 0
            
            for eip in response.publicips:
                eip_info = {
                    'id': eip.id,
                    'public_ip': eip.public_ip_address,
                    'private_ip': getattr(eip, 'private_ip_address', None),
                    'status': eip.status,
                    'type': getattr(eip, 'type', None),
                    'bandwidth_size': getattr(eip, 'bandwidth_size', None),
                    'create_time': getattr(eip, 'create_time', None),
                    'associate_instance_type': getattr(eip, 'associate_instance_type', None),
                    'associate_instance_id': getattr(eip, 'associate_instance_id', None)
                }
                
                # Verificar si está sin usar
                if eip.status == 'DOWN' or not getattr(eip, 'associate_instance_id', None):
                    unused_count += 1
                    self._add_finding(
                        'NET-005',
                        'LOW',
                        f'Elastic IP sin utilizar en {region}: {eip.public_ip_address}',
                        {
                            'eip_id': eip.id, 
                            'ip': eip.public_ip_address, 
                            'region': region,
                            'monthly_cost_estimate': '$5-10 USD'
                        }
                    )
                
                eips.append(eip_info)
            
            self.logger.info(f"Recolectadas {len(eips)} EIPs en {region} ({unused_count} sin usar)")
            return eips
            
        except Exception as e:
            self.logger.error(f"Error recolectando EIPs en {region}: {str(e)}")
            return None
    
    async def _analyze_exposed_resources_safe(self, region: str) -> Optional[List[Dict]]:
        """Analizar recursos expuestos con manejo de errores mejorado"""
        try:
            client = self._get_ecs_client(region)
            if not client:
                return None
                
            request = ListServersDetailsRequest()
            request.limit = 100
            response = client.list_servers_details(request)
            
            exposed = []
            servers_with_public_ip = 0
            
            for server in response.servers:
                public_ips = self._extract_public_ips(server)
                
                if public_ips:
                    servers_with_public_ip += 1
                    
                    # Analizar security groups
                    for sg in getattr(server, 'security_groups', []):
                        sg_id = sg.id if hasattr(sg, 'id') else sg.get('id') if isinstance(sg, dict) else None
                        
                        if sg_id:
                            exposed_ports = await self._check_exposed_ports(sg_id, region)
                            
                            if exposed_ports:
                                critical_ports = [p for p in exposed_ports if p['port'] in CRITICAL_PORTS]
                                
                                if critical_ports:
                                    exposed.append({
                                        'server_id': server.id,
                                        'server_name': server.name,
                                        'public_ips': public_ips,
                                        'exposed_ports': critical_ports,
                                        'region': region
                                    })
                                    
                                    self._add_finding(
                                        'NET-003',
                                        'CRITICAL',
                                        f'Servidor {server.name} con puertos críticos expuestos en {region}',
                                        {
                                            'server_id': server.id,
                                            'ports': [p['port'] for p in critical_ports],
                                            'public_ips': public_ips,
                                            'region': region
                                        }
                                    )
            
            self.logger.info(f"Analizados {len(response.servers)} servidores en {region} ({servers_with_public_ip} con IP pública)")
            return exposed
            
        except Exception as e:
            self.logger.error(f"Error analizando recursos expuestos en {region}: {str(e)}")
            return None
    
    def _extract_public_ips(self, server) -> List[str]:
        """Extraer IPs públicas de un servidor"""
        public_ips = []
        
        if hasattr(server, 'addresses') and server.addresses:
            for network_name, addr_list in server.addresses.items():
                for addr in addr_list:
                    # Manejar diferentes formatos
                    if hasattr(addr, 'OS-EXT-IPS:type'):
                        if getattr(addr, 'OS-EXT-IPS:type') == 'floating':
                            public_ips.append(addr.addr)
                    elif isinstance(addr, dict):
                        if addr.get('OS-EXT-IPS:type') == 'floating':
                            public_ips.append(addr.get('addr'))
        
        # También verificar publicIp directo
        if hasattr(server, 'publicIp') and server.publicIp:
            public_ips.extend(server.publicIp)
            
        return list(set(public_ips))  # Eliminar duplicados
    
    def _add_inventory_based_finding(self, region: str, region_info: Dict):
        """Agregar hallazgo basado en inventario cuando no hay acceso a la región"""
        self._add_finding(
            f'NET-INV-{region[:3].upper()}',
            'MEDIUM',
            f'No se pudo analizar {region_info["resources"]} recursos en {region}',
            {
                'region': region,
                'total_resources': region_info['resources'],
                'breakdown': {k: v for k, v in region_info.items() if k != 'resources'},
                'reason': 'Sin autorización o conectividad a la región',
                'recommendation': 'Verificar manualmente la configuración de seguridad'
            }
        )
    
    def _add_consolidated_findings(self, results: Dict):
        """Agregar hallazgos consolidados basados en análisis multi-región"""
        # Análisis de distribución de recursos
        total_vpcs = sum(len(vpcs) for vpcs in results['vpcs'].values())
        total_from_inventory = sum(self.inventory_by_region[r].get('vpcs', 0) for r in self.inventory_by_region)
        
        if total_from_inventory > 15:
            self._add_finding(
                'NET-CONSOLIDATION-001',
                'MEDIUM',
                f'Arquitectura multi-VPC compleja: {total_from_inventory} VPCs en 5 regiones',
                {
                    'vpcs_by_region': {r: self.inventory_by_region[r].get('vpcs', 0) 
                                     for r in self.inventory_by_region if self.inventory_by_region[r].get('vpcs', 0) > 0},
                    'recommendation': 'Evaluar consolidación de VPCs y uso de VPC Peering'
                }
            )
        
        # Desbalance regional
        ba_resources = self.inventory_by_region['LA-Buenos Aires1']['resources']
        total_resources = sum(r['resources'] for r in self.inventory_by_region.values())
        concentration = (ba_resources / total_resources) * 100
        
        if concentration > 80:
            self._add_finding(
                'NET-REGIONAL-001',
                'HIGH',
                f'Alta concentración de recursos en una región: {concentration:.1f}% en Buenos Aires',
                {
                    'buenos_aires': ba_resources,
                    'total': total_resources,
                    'risk': 'Single point of failure regional',
                    'recommendation': 'Implementar arquitectura multi-región para alta disponibilidad'
                }
            )
        
        # Recursos huérfanos en regiones menores
        minor_regions = ['CN-Hong Kong', 'AP-Bangkok', 'AP-Singapore']
        minor_resources = sum(self.inventory_by_region[r]['resources'] for r in minor_regions)
        
        if minor_resources > 0 and minor_resources < 20:
            self._add_finding(
                'NET-SPRAWL-001',
                'LOW',
                f'Recursos dispersos en regiones con pocos servicios',
                {
                    'regions': {r: self.inventory_by_region[r]['resources'] for r in minor_regions},
                    'total_resources': minor_resources,
                    'recommendation': 'Considerar migración a regiones principales para reducir complejidad'
                }
            )
    
    def _is_dangerous_rule(self, rule) -> bool:
        """Verificar si una regla es peligrosa"""
        if getattr(rule, 'direction', None) != 'ingress':
            return False
            
        remote_ip = getattr(rule, 'remote_ip_prefix', None)
        if remote_ip not in ['0.0.0.0/0', '::/0']:
            return False
            
        # Es peligrosa si permite acceso desde Internet
        return True
    
    def _is_critical_exposure(self, rule) -> bool:
        """Verificar si es una exposición crítica"""
        if not self._is_dangerous_rule(rule):
            return False
            
        port_min = getattr(rule, 'port_range_min', None)
        port_max = getattr(rule, 'port_range_max', None)
        
        if port_min and port_max:
            # Verificar si incluye puertos críticos
            for port in CRITICAL_PORTS:
                if port_min <= port <= port_max:
                    return True
                    
        return False
    
    async def _check_exposed_ports(self, sg_id: str, region: str) -> List[Dict]:
        """Verificar puertos expuestos en un security group"""
        exposed_ports = []
        
        try:
            client = self._get_vpc_client(region)
            if not client:
                return []
                
            request = ListSecurityGroupRulesRequest()
            request.security_group_id = sg_id
            response = client.list_security_group_rules(request)
            
            for rule in response.security_group_rules:
                if (getattr(rule, 'direction', None) == 'ingress' and 
                    getattr(rule, 'remote_ip_prefix', None) in ['0.0.0.0/0', '::/0']):
                    
                    port_min = getattr(rule, 'port_range_min', None)
                    port_max = getattr(rule, 'port_range_max', None)
                    
                    if port_min and port_max:
                        # Solo reportar puertos críticos
                        for port in CRITICAL_PORTS:
                            if port_min <= port <= port_max:
                                exposed_ports.append({
                                    'port': port,
                                    'protocol': getattr(rule, 'protocol', 'tcp'),
                                    'description': CRITICAL_PORTS[port]
                                })
                    
        except Exception as e:
            self.logger.debug(f"Error verificando puertos expuestos en SG {sg_id}: {str(e)}")
            
        return exposed_ports
    
    def _analyze_security_group_rule(self, rule: Any, sg_name: str, region: str, attached_count: int):
        """Analiza la regla y genera hallazgos con contexto ampliado"""
        if not self._is_dangerous_rule(rule):
            return

        port_min = getattr(rule, "port_range_min", None)
        port_max = getattr(rule, "port_range_max", None)

        # --- (1) CRÍTICOS ---------------------------------------------------
        if port_min and port_max:
            critical_in_range = [
                f"{p} ({CRITICAL_PORTS[p]})"
                for p in CRITICAL_PORTS
                if port_min <= p <= port_max
            ]

            if critical_in_range:
                self._add_finding(
                    "NET-004",
                    "CRITICAL",
                    (
                        f"Puertos críticos expuestos a Internet en {region} - "
                        f"SG «{sg_name}» ({attached_count} instancias)"
                    ),
                    {
                        "security_group": sg_name,
                        "rule_id": rule.id,
                        "port_range": f"{port_min}-{port_max}",
                        "exposed_ports": critical_in_range,
                        "assigned_instances": attached_count,
                        "protocol": getattr(rule, "protocol", "any"),
                        "region": region,
                    },
                )
            return  # ya registrado, no necesita NET-006

        # --- (2) PERMITE TODO ----------------------------------------------
        self._add_finding(
            "NET-006",
            "HIGH",
            (
                f"Regla permite TODO el tráfico desde Internet en {region} - "
                f"SG «{sg_name}» ({attached_count} instancias)"
            ),
            {
                "security_group": sg_name,
                "rule_id": rule.id,
                "protocol": getattr(rule, "protocol", "any"),
                "assigned_instances": attached_count,
                "region": region,
                "risk": "Exposición completa del recurso",
            },
        )
    
    def _check_vpc_issues(self, vpc: Any) -> bool:
        """Verificar problemas en configuración de VPC"""
        try:
            if hasattr(vpc, 'cidr') and vpc.cidr:
                network = ipaddress.ip_network(vpc.cidr)
                # Más de 65k hosts es excesivo para la mayoría de casos
                return network.prefixlen < 16
        except:
            pass
        return False
    
    def _is_public_subnet(self, subnet: Any) -> bool:
        """Determinar si una subnet es pública"""
        return bool(getattr(subnet, 'gateway_ip', None))
    
    def _requires_public_access(self, subnet: Any) -> bool:
        """Verificar si la subnet requiere acceso público"""
        public_keywords = ['dmz', 'public', 'frontend', 'web', 'lb', 'load', 'nat', 'bastion']
        subnet_name = getattr(subnet, 'name', '').lower()
        return any(keyword in subnet_name for keyword in public_keywords)
    
    def _add_finding(self, finding_id: str, severity: str, message: str, details: dict):
        """Agregar un hallazgo de seguridad"""
        finding = {
            'id': finding_id,
            'severity': severity,
            'message': message,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.findings.append(finding)
        self.logger.log_finding(severity, finding_id, message, details)
    
    def _calculate_statistics(self, results: dict) -> dict:
        """Calcular estadísticas del análisis de red"""
        stats = {
            # Datos recolectados
            'collected': {
                'vpcs': sum(len(vpcs) for vpcs in results['vpcs'].values()),
                'subnets': sum(len(subnets) for subnets in results['subnets'].values()),
                'security_groups': sum(len(sgs) for sgs in results['security_groups'].values()),
                'elastic_ips': sum(len(eips) for eips in results['elastic_ips'].values()),
                'regions_analyzed': len([r for r in results['vpcs'] if results['vpcs'][r]])
            },
            # Datos del inventario
            'inventory': {
                'total_vpcs': 20,
                'total_security_groups': 17,
                'total_eips': 10,
                'total_regions': 5,
                'total_resources': 437
            },
            # Hallazgos
            'findings_by_severity': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            },
            # Métricas de exposición
            'exposure_metrics': {
                'exposed_resources': len(results['exposed_resources']),
                'critical_ports_exposed': sum(len(r['exposed_ports']) for r in results['exposed_resources']),
                'regions_with_exposures': len(set(r['region'] for r in results['exposed_resources']))
            }
        }
        
        # Contar hallazgos por severidad
        for finding in self.findings:
            stats['findings_by_severity'][finding['severity']] += 1
        
        return stats