#!/usr/bin/env python3
"""
Colector de configuraciones de red para Huawei Cloud
"""

import asyncio
from datetime import datetime
from typing import Dict, List, Any
import ipaddress
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkvpc.v2 import *
from huaweicloudsdkecs.v2 import *
from huaweicloudsdkcore.region.region import Region
from utils.logger import SecurityLogger
from config.settings import (
    HUAWEI_ACCESS_KEY, HUAWEI_SECRET_KEY,
    HUAWEI_PROJECT_ID, REGIONS
)
from config.constants import CRITICAL_PORTS
from utils.multi_region_client import MultiRegionClient

class NetworkCollector(MultiRegionClient):
    """Colector de configuraciones de seguridad de red"""
    
    def __init__(self):
        self.logger = SecurityLogger('NetworkCollector')
        self.findings = []
        self.credentials = BasicCredentials(
            HUAWEI_ACCESS_KEY,
            HUAWEI_SECRET_KEY,
            HUAWEI_PROJECT_ID
        )
        
    def _get_vpc_client(self, region: str):
        """Obtener cliente VPC para una región"""
        credentials = self.get_credentials_for_region(region)
        
        return VpcClient.new_builder() \
            .with_credentials(credentials) \
            .with_region(VpcRegion.value_of(region)) \
            .build()
    
    def _get_ecs_client(self, region: str):
        """Obtener cliente ECS para una región"""
        credentials = self.get_credentials_for_region(region)
        
        return EcsClient.new_builder() \
            .with_credentials(credentials) \
            .with_region(EcsRegion.value_of(region)) \
            .build()
    
    async def collect_all(self) -> Dict[str, Any]:
        """Recolectar todos los datos de red"""
        self.logger.info("Iniciando recolección de datos de red")
        
        results = {
            'vpcs': {},
            'subnets': {},
            'security_groups': {},
            'network_acls': {},
            'elastic_ips': {},
            'nat_gateways': {},
            'vpn_connections': {},
            'exposed_resources': [],
            'security_group_analysis': {},
            'findings': self.findings,
            'statistics': {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Recolectar datos por región
        for region in REGIONS:
            region_name = self.get_region_display_name(region)
            self.logger.info(f"Analizando región: {region_name} ({region})")
            
            try:
                results['vpcs'][region] = await self._collect_vpcs(region)
                results['subnets'][region] = await self._collect_subnets(region)
                results['security_groups'][region] = await self._collect_security_groups(region)
                results['security_group_analysis'][region] = await self._analyze_security_groups_usage(region)
                results['network_acls'][region] = await self._collect_network_acls(region)
                results['elastic_ips'][region] = await self._collect_elastic_ips(region)
                results['exposed_resources'].extend(await self._analyze_exposed_resources(region))
                
                # Log de éxito
                self.logger.info(f"✓ Región {region_name} analizada exitosamente")
                
            except Exception as e:
                self.logger.error(f"Error en región {region_name}: {str(e)}")
                
                # Si es error de autenticación/proyecto, agregarlo como finding
                if "does not match with the project" in str(e) or "401" in str(e):
                    self._add_finding(
                        'NET-010',
                        'INFO',
                        f'No se pudo acceder a la región {region_name}',
                        {
                            'region': region,
                            'error': 'Posible falta de permisos o región no habilitada',
                            'recommendation': 'Verificar permisos IAM para esta región'
                        }
                    )
        
        # Calcular estadísticas
        results['statistics'] = self._calculate_statistics(results)
        
        self.logger.info(f"Recolección de red completada. Hallazgos: {len(self.findings)}")
        return results
    
    async def _collect_vpcs(self, region: str) -> List[Dict]:
        """Recolectar información de VPCs"""
        vpcs = []
        try:
            client = self._get_vpc_client(region)
            request = ListVpcsRequest()
            response = client.list_vpcs(request)
            
            for vpc in response.vpcs:
                vpc_info = {
                    'id': vpc.id,
                    'name': vpc.name,
                    'cidr': vpc.cidr,
                    'status': vpc.status,
                    'description': vpc.description,
                    'enterprise_project_id': vpc.enterprise_project_id,
                    'created_at': vpc.created_at,
                    'routes': []
                }
                
                # Verificar configuración de red
                if self._check_vpc_issues(vpc):
                    self._add_finding(
                        'NET-001',
                        'MEDIUM',
                        f'VPC con configuración subóptima: {vpc.name}',
                        {'vpc_id': vpc.id, 'region': region}
                    )
                
                vpcs.append(vpc_info)
                
        except Exception as e:
            self.logger.error(f"Error recolectando VPCs en {region}: {str(e)}")
            
        return vpcs
    
    async def _collect_subnets(self, region: str) -> List[Dict]:
        """Recolectar información de subnets"""
        subnets = []
        try:
            client = self._get_vpc_client(region)
            request = ListSubnetsRequest()
            response = client.list_subnets(request)
            
            for subnet in response.subnets:
                subnet_info = {
                    'id': subnet.id,
                    'name': subnet.name,
                    'cidr': subnet.cidr,
                    'vpc_id': subnet.vpc_id,
                    'gateway_ip': subnet.gateway_ip,
                    'dhcp_enable': subnet.dhcp_enable,
                    'primary_dns': subnet.primary_dns,
                    'secondary_dns': subnet.secondary_dns,
                    'availability_zone': subnet.availability_zone
                }
                
                # Verificar si es subnet pública innecesaria
                if self._is_public_subnet(subnet) and not self._requires_public_access(subnet):
                    self._add_finding(
                        'NET-002',
                        'HIGH',
                        f'Subnet pública sin justificación: {subnet.name}',
                        {'subnet_id': subnet.id, 'cidr': subnet.cidr, 'region': region}
                    )
                
                subnets.append(subnet_info)
                
        except Exception as e:
            self.logger.error(f"Error recolectando subnets en {region}: {str(e)}")
            
        return subnets
    
    async def _collect_security_groups(self, region: str) -> List[Dict]:
        """Recolectar y analizar security groups"""
        security_groups = []
        try:
            client = self._get_vpc_client(region)
            request = ListSecurityGroupsRequest()
            response = client.list_security_groups(request)
            
            for sg in response.security_groups:
                sg_info = {
                    'id': sg.id,
                    'name': sg.name,
                    'description': sg.description,
                    'vpc_id': getattr(sg, 'vpc_id', None),
                    'enterprise_project_id': sg.enterprise_project_id,
                    'rules': []
                }
                
                # Obtener reglas detalladas
                rules_request = ListSecurityGroupRulesRequest()
                rules_request.security_group_id = sg.id
                rules_response = client.list_security_group_rules(rules_request)
                
                for rule in rules_response.security_group_rules:
                    rule_info = {
                        'id': rule.id,
                        'direction': rule.direction,
                        'protocol': rule.protocol,
                        'ethertype': rule.ethertype,
                        'description': rule.description,
                        'remote_ip_prefix': rule.remote_ip_prefix,
                        'remote_group_id': rule.remote_group_id,
                        'port_range_min': rule.port_range_min,
                        'port_range_max': rule.port_range_max
                    }
                    
                    # Analizar reglas peligrosas
                    self._analyze_security_group_rule(rule, sg.name, region)
                    
                    sg_info['rules'].append(rule_info)
                
                security_groups.append(sg_info)
                
        except Exception as e:
            self.logger.error(f"Error recolectando security groups en {region}: {str(e)}")
            
        return security_groups
    
    async def _collect_network_acls(self, region: str) -> List[Dict]:
        """Recolectar Network ACLs"""
        nacls = []
        try:
            client = self._get_vpc_client(region)
            # API específica de Huawei Cloud para Network ACLs
            # Implementar según documentación
            pass
        except Exception as e:
            self.logger.error(f"Error recolectando NACLs en {region}: {str(e)}")
            
        return nacls
    
    async def _collect_elastic_ips(self, region: str) -> List[Dict]:
        """Recolectar Elastic IPs"""
        eips = []
        
        try:
            # Intentar con el cliente EIP si está disponible
            try:
                from huaweicloudsdkeip.v2 import (
                    EipClient, ListPublicipsRequest, EipRegion
                )
                
                credentials = self.get_credentials_for_region(region)
                eip_client = EipClient.new_builder() \
                    .with_credentials(credentials) \
                    .with_region(EipRegion.value_of(region)) \
                    .build()
                
                request = ListPublicipsRequest()
                response = eip_client.list_publicips(request)
                publicips = response.publicips
                
            except ImportError:
                # Si no está disponible el módulo EIP, usar VPC
                self.logger.warning(f"Módulo EIP no disponible, usando método alternativo para {region}")
                vpc_client = self._get_vpc_client(region)
                
                # Intentar con el método de VPC v2
                from huaweicloudsdkvpc.v2 import ListPublicipsRequest as VpcListPublicipsRequest
                
                request = VpcListPublicipsRequest()
                response = vpc_client.list_publicips(request)
                publicips = response.publicips
            
            # Procesar las IPs públicas
            for eip in publicips:
                eip_info = {
                    'id': getattr(eip, 'id', 'unknown'),
                    'public_ip_address': getattr(eip, 'public_ip_address', 'unknown'),
                    'private_ip_address': getattr(eip, 'private_ip_address', None),
                    'status': getattr(eip, 'status', 'unknown'),
                    'bandwidth_id': getattr(eip, 'bandwidth_id', None),
                    'bandwidth_size': getattr(eip, 'bandwidth_size', None),
                    'created_at': getattr(eip, 'create_time', getattr(eip, 'created_at', None)),
                    'type': getattr(eip, 'type', None),
                    'port_id': getattr(eip, 'port_id', None),
                    'instance_type': getattr(eip, 'instance_type', None),
                    'instance_id': getattr(eip, 'instance_id', None)
                }
                
                # Verificar IPs sin uso
                if eip_info['status'] == 'DOWN' or not eip_info['port_id']:
                    self._add_finding(
                        'NET-005',
                        'LOW',
                        f'Elastic IP sin utilizar: {eip_info["public_ip_address"]}',
                        {
                            'eip_id': eip_info['id'],
                            'ip': eip_info['public_ip_address'],
                            'region': self.get_region_display_name(region),
                            'cost_estimate': '$5-10/mes desperdiciados'
                        }
                    )
                
                eips.append(eip_info)
                
        except Exception as e:
            self.logger.error(f"Error recolectando EIPs en {self.get_region_display_name(region)}: {str(e)}")
            
            # Si es un error de importación o método no encontrado, log pero continuar
            if "ListPublicipsRequest" in str(e) or "has no attribute" in str(e):
                self.logger.info(f"API de EIP no disponible en {region}, continuando sin EIPs")
            
        return eips
    
    async def _analyze_exposed_resources(self, region: str) -> List[Dict]:
        """Analizar recursos expuestos a Internet"""
        exposed = []
        try:
            ecs_client = self._get_ecs_client(region)
            request = ListServersDetailsRequest()
            response = ecs_client.list_servers_details(request)
            
            for server in response.servers:
                # Verificar si tiene IP pública
                public_ips = []
                for addr_set in server.addresses.values():
                    for addr in addr_set:
                        if addr.get('OS-EXT-IPS:type') == 'floating':
                            public_ips.append(addr['addr'])
                
                if public_ips:
                    # Obtener security groups del servidor
                    for sg in server.security_groups:
                        exposed_ports = await self._check_exposed_ports(sg['id'], region)
                        
                        if exposed_ports:
                            exposed_info = {
                                'server_id': server.id,
                                'server_name': server.name,
                                'public_ips': public_ips,
                                'exposed_ports': exposed_ports,
                                'security_groups': [sg['name'] for sg in server.security_groups],
                                'region': region
                            }
                            exposed.append(exposed_info)
                            
                            # Verificar puertos críticos
                            critical_exposed = [
                                p for p in exposed_ports 
                                if p['port'] in CRITICAL_PORTS
                            ]
                            
                            if critical_exposed:
                                self._add_finding(
                                    'NET-003',
                                    'CRITICAL',
                                    f'Servidor con puertos críticos expuestos: {server.name}',
                                    {
                                        'server_id': server.id,
                                        'ports': critical_exposed,
                                        'public_ips': public_ips,
                                        'region': region
                                    }
                                )
                                
        except Exception as e:
            self.logger.error(f"Error analizando recursos expuestos en {region}: {str(e)}")
            
        return exposed
    
    async def _check_exposed_ports(self, sg_id: str, region: str) -> List[Dict]:
        """Verificar puertos expuestos en un security group"""
        exposed_ports = []
        try:
            client = self._get_vpc_client(region)
            request = ListSecurityGroupRulesRequest()
            request.security_group_id = sg_id
            response = client.list_security_group_rules(request)
            
            for rule in response.security_group_rules:
                if (rule.direction == 'ingress' and 
                    rule.remote_ip_prefix in ['0.0.0.0/0', '::/0']):
                    
                    if rule.port_range_min and rule.port_range_max:
                        for port in range(rule.port_range_min, rule.port_range_max + 1):
                            exposed_ports.append({
                                'port': port,
                                'protocol': rule.protocol,
                                'description': CRITICAL_PORTS.get(port, 'Unknown')
                            })
                    
        except Exception as e:
            self.logger.error(f"Error verificando puertos expuestos: {str(e)}")
            
        return exposed_ports
    
    def _analyze_security_group_rule(self, rule: Any, sg_name: str, region: str):
        """Analizar regla de security group para detectar problemas"""
        # Reglas de entrada desde 0.0.0.0/0
        if (rule.direction == 'ingress' and 
            rule.remote_ip_prefix in ['0.0.0.0/0', '::/0']):
            
            # Verificar puertos críticos
            if rule.port_range_min and rule.port_range_max:
                for port in range(rule.port_range_min, rule.port_range_max + 1):
                    if port in CRITICAL_PORTS:
                        self._add_finding(
                            'NET-004',
                            'CRITICAL',
                            f'Puerto crítico {port} ({CRITICAL_PORTS[port]}) expuesto a Internet',
                            {
                                'security_group': sg_name,
                                'rule_id': rule.id,
                                'port': port,
                                'protocol': rule.protocol,
                                'region': region
                            }
                        )
            
            # Regla demasiado permisiva (todos los puertos)
            elif not rule.port_range_min and not rule.port_range_max:
                self._add_finding(
                    'NET-006',
                    'HIGH',
                    f'Regla permite todo el tráfico desde Internet',
                    {
                        'security_group': sg_name,
                        'rule_id': rule.id,
                        'protocol': rule.protocol,
                        'region': region
                    }
                )
    
    def _check_vpc_issues(self, vpc: Any) -> bool:
        """Verificar problemas en configuración de VPC"""
        issues = False
        
        # Verificar CIDR muy grande
        try:
            network = ipaddress.ip_network(vpc.cidr)
            if network.prefixlen < 16:  # Más de 65k hosts
                issues = True
        except:
            pass
            
        return issues
    
    def _is_public_subnet(self, subnet: Any) -> bool:
        """Determinar si una subnet es pública"""
        # Lógica específica de Huawei Cloud
        # Por ahora, verificar si tiene gateway IP
        return bool(subnet.gateway_ip)
    
    def _requires_public_access(self, subnet: Any) -> bool:
        """Verificar si la subnet requiere acceso público"""
        # Implementar lógica según tags o nombre
        public_keywords = ['dmz', 'public', 'frontend', 'lb', 'load-balancer']
        return any(keyword in subnet.name.lower() for keyword in public_keywords)
    
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
            'total_vpcs': sum(len(vpcs) for vpcs in results['vpcs'].values()),
            'total_subnets': sum(len(subnets) for subnets in results['subnets'].values()),
            'total_security_groups': sum(len(sgs) for sgs in results['security_groups'].values()),
            'total_elastic_ips': sum(len(eips) for eips in results['elastic_ips'].values()),
            'exposed_resources': len(results['exposed_resources']),
            'critical_ports_exposed': 0,
            'unused_elastic_ips': 0,
            'overly_permissive_rules': 0,
            'findings_by_severity': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            }
        }
        
        # Contar puertos críticos expuestos
        for resource in results['exposed_resources']:
            stats['critical_ports_exposed'] += len([
                p for p in resource['exposed_ports'] 
                if p['port'] in CRITICAL_PORTS
            ])
        
        # Contar hallazgos por severidad
        for finding in self.findings:
            stats['findings_by_severity'][finding['severity']] += 1
        
        return stats