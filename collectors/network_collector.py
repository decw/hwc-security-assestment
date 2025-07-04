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
from utils.logger import SecurityLogger
from config.settings import (
    HUAWEI_ACCESS_KEY, HUAWEI_SECRET_KEY,
    HUAWEI_PROJECT_ID, REGIONS
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
        
    def _get_vpc_client(self, region: str):
        """Obtener cliente VPC para una región"""
        return VpcClient.new_builder() \
            .with_credentials(self.credentials) \
            .with_region(VpcRegion.value_of(region)) \
            .build()
    
    def _get_ecs_client(self, region: str):
        """Obtener cliente ECS para una región"""
        return EcsClient.new_builder() \
            .with_credentials(self.credentials) \
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
            'findings': self.findings,
            'statistics': {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Recolectar datos por región
        for region in REGIONS:
            self.logger.info(f"Analizando región: {region}")
            try:
                results['vpcs'][region] = await self._collect_vpcs(region)
                results['subnets'][region] = await self._collect_subnets(region)
                results['security_groups'][region] = await self._collect_security_groups(region)
                results['network_acls'][region] = await self._collect_network_acls(region)
                results['elastic_ips'][region] = await self._collect_elastic_ips(region)
                results['exposed_resources'].extend(await self._analyze_exposed_resources(region))
            except Exception as e:
                self.logger.error(f"Error en región {region}: {str(e)}")
        
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
            client = self._get_vpc_client(region)
            request = ListPublicipsRequest()
            response = client.list_publicips(request)
            
            for eip in response.publicips:
                eip_info = {
                    'id': eip.id,
                    'public_ip_address': eip.public_ip_address,
                    'private_ip_address': eip.private_ip_address,
                    'status': eip.status,
                    'bandwidth_id': eip.bandwidth_id,
                    'bandwidth_size': eip.bandwidth_size,
                    'bandwidth_share_type': eip.bandwidth_share_type,
                    'created_at': eip.created_at,
                    'tenant_id': eip.tenant_id,
                    'type': eip.type,
                    'port_id': getattr(eip, 'port_id', None)
                }
                
                # Verificar IPs sin uso
                if eip.status == 'DOWN' or not eip.port_id:
                    self._add_finding(
                        'NET-005',
                        'LOW',
                        f'Elastic IP sin utilizar: {eip.public_ip_address}',
                        {'eip_id': eip.id, 'ip': eip.public_ip_address, 'region': region}
                    )
                
                eips.append(eip_info)
                
        except Exception as e:
            self.logger.error(f"Error recolectando EIPs en {region}: {str(e)}")
            
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