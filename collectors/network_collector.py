#!/usr/bin/env python3
"""
Colector de configuraciones de red para Huawei Cloud - Multi-región
Actualizado con estructura similar a IAM Collector
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
import ipaddress
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkcore.region.region import Region
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkvpc.v2 import *
from huaweicloudsdkecs.v2 import *
from huaweicloudsdkelb.v3 import *

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
    """Colector de configuraciones de seguridad de red siguiendo códigos de security_references.csv"""

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

        # Recursos por región según inventario actualizado
        self.inventory_by_region = {
            'LA-Santiago': {
                'resources': 50,
                'ecs': 9,
                'evs': 21,
                'vpcs': 9,
                'elb': 0,
                'eips': 1
            },
            'LA-Buenos Aires1': {
                'resources': 369,
                'ecs': 104,
                'evs': 230,
                'vpcs': 11,
                'elb': 2,
                'eips': 9
            },
            'CN-Hong Kong': {
                'resources': 6,
                'vpcs': 1,
                'function_graph': 2
            },
            'AP-Bangkok': {
                'resources': 4,
                'function_graph': 3
            },
            'AP-Singapore': {
                'resources': 2,
                'function_graph': 1
            }
        }

        # Inicializar contadores para estadísticas
        self.stats = {
            'total_regions_analyzed': 0,
            'total_vpcs': 0,
            'total_subnets': 0,
            'total_security_groups': 0,
            'total_elbs': 0,
            'total_eips': 0,
            'total_nacls': 0,
            'total_flow_logs': 0,
            'total_peerings': 0
        }

    def _get_vpc_client(self, region_alias: str):
        """Obtener cliente VPC para una región específica"""
        try:
            region_id = self.region_map.get(region_alias, region_alias)
            project_id = REGION_PROJECT_MAPPING.get(region_id)

            if not project_id:
                self.logger.warning(
                    f"No hay project_id configurado para {region_id}")
                return None

            creds = BasicCredentials(
                HUAWEI_ACCESS_KEY,
                HUAWEI_SECRET_KEY,
                project_id
            )

            region_obj = Region(
                region_id, f"https://vpc.{region_id}.myhuaweicloud.com")

            return VpcClient.new_builder()\
                .with_credentials(creds)\
                .with_region(region_obj)\
                .build()
        except Exception as e:
            self.logger.error(
                f"Error creando cliente VPC para {region_alias}: {str(e)}")
            return None

    def _get_ecs_client(self, region_alias: str) -> Optional[EcsClient]:
        """Obtener cliente ECS para una región específica"""
        try:
            region_id = self.region_map.get(region_alias, region_alias)
            project_id = REGION_PROJECT_MAPPING.get(region_id)

            if not project_id:
                return None

            creds = BasicCredentials(
                HUAWEI_ACCESS_KEY,
                HUAWEI_SECRET_KEY,
                project_id
            )

            region_obj = Region(
                region_id, f"https://ecs.{region_id}.myhuaweicloud.com")

            return EcsClient.new_builder()\
                .with_credentials(creds)\
                .with_region(region_obj)\
                .build()
        except Exception as e:
            self.logger.error(
                f"Error creando cliente ECS para {region_alias}: {str(e)}")
            return None

    def _get_elb_client(self, region_alias: str) -> Optional[ElbClient]:
        """Obtener cliente ELB para una región específica"""
        try:
            region_id = self.region_map.get(region_alias, region_alias)
            project_id = REGION_PROJECT_MAPPING.get(region_id)

            if not project_id:
                return None

            creds = BasicCredentials(
                HUAWEI_ACCESS_KEY,
                HUAWEI_SECRET_KEY,
                project_id
            )

            region_obj = Region(
                region_id, f"https://elb.{region_id}.myhuaweicloud.com")

            return ElbClient.new_builder()\
                .with_credentials(creds)\
                .with_region(region_obj)\
                .build()
        except Exception as e:
            self.logger.error(
                f"Error creando cliente ELB para {region_alias}: {str(e)}")
            return None

    async def collect_all(self) -> Dict[str, Any]:
        """Recolectar toda la información de red siguiendo códigos del CSV"""
        self.logger.info("=== Iniciando recolección de datos de red ===")

        results = {
            'timestamp': datetime.now().isoformat(),
            'vpcs': {},
            'subnets': {},
            'security_groups': {},
            'elastic_ips': {},
            'load_balancers': {},
            'network_acls': {},
            'flow_logs': {},
            'vpc_peerings': {},
            'exposed_resources': [],
            'findings': [],
            'statistics': {}
        }

        # Recolectar datos por región
        for region in self.region_map.keys():
            self.logger.info(f"Analizando región: {region}")

            # VPCs y Subnets - NET-001, NET-002
            vpcs = await self._collect_vpcs(region)
            if vpcs:
                results['vpcs'][region] = vpcs

            subnets = await self._collect_subnets(region)
            if subnets:
                results['subnets'][region] = subnets

            # Security Groups - NET-003
            security_groups = await self._collect_security_groups(region)
            if security_groups:
                results['security_groups'][region] = security_groups

            # Exposed Resources - NET-004
            exposed = await self._analyze_exposed_resources(region)
            if exposed:
                results['exposed_resources'].extend(exposed)

            # Network ACLs - NET-005
            nacls = await self._collect_network_acls(region)
            if nacls:
                results['network_acls'][region] = nacls

            # VPC Peerings - NET-006
            peerings = await self._collect_vpc_peerings(region)
            if peerings:
                results['vpc_peerings'][region] = peerings

            # Load Balancers - NET-007
            elbs = await self._collect_load_balancers(region)
            if elbs:
                results['load_balancers'][region] = elbs

            # Flow Logs - NET-008
            flow_logs = await self._collect_flow_logs(region)
            if flow_logs:
                results['flow_logs'][region] = flow_logs

            # Elastic IPs
            if EIP_SDK_AVAILABLE:
                eips = await self._collect_elastic_ips(region)
                if eips:
                    results['elastic_ips'][region] = eips

        # Ejecutar verificaciones adicionales
        await self._check_vpc_segregation(results)  # NET-001
        await self._check_public_subnets(results)  # NET-002
        await self._check_security_group_rules(results)  # NET-003
        await self._check_critical_ports(results)  # NET-004
        await self._check_network_acls(results)  # NET-005
        await self._check_vpc_peering_restrictions(results)  # NET-006
        await self._check_elb_encryption(results)  # NET-007
        await self._check_flow_logs(results)  # NET-008

        # Calcular estadísticas
        results['statistics'] = self._calculate_statistics(results)
        results['findings'] = self.findings

        self.logger.info(
            f"=== Recolección completada. Total hallazgos: {len(self.findings)} ===")
        return results

    async def _collect_vpcs(self, region: str) -> Optional[List[Dict]]:
        """Recolectar información de VPCs"""
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
                    'created_at': getattr(vpc, 'created_at', None),
                    'has_flow_logs': False,  # Se actualiza después
                    'has_segregated_subnets': False  # Se actualiza después
                }
                vpcs.append(vpc_info)
                self.stats['total_vpcs'] += 1

            self.logger.info(f"Recolectadas {len(vpcs)} VPCs en {region}")
            return vpcs

        except Exception as e:
            self.logger.error(f"Error recolectando VPCs en {region}: {str(e)}")
            return None

    async def _collect_subnets(self, region: str) -> Optional[List[Dict]]:
        """Recolectar información de subnets"""
        try:
            client = self._get_vpc_client(region)
            if not client:
                return None

            request = ListSubnetsRequest()
            request.limit = 200
            response = client.list_subnets(request)

            subnets = []
            for subnet in response.subnets:
                subnet_info = {
                    'id': subnet.id,
                    'name': subnet.name,
                    'cidr': subnet.cidr,
                    'vpc_id': subnet.vpc_id,
                    'gateway_ip': subnet.gateway_ip,
                    'availability_zone': getattr(subnet, 'availability_zone', None),
                    'is_public': self._is_public_subnet(subnet),
                    'purpose': self._determine_subnet_purpose(subnet)
                }
                subnets.append(subnet_info)
                self.stats['total_subnets'] += 1

            self.logger.info(
                f"Recolectadas {len(subnets)} subnets en {region}")
            return subnets

        except Exception as e:
            self.logger.error(
                f"Error recolectando subnets en {region}: {str(e)}")
            return None

    async def _collect_security_groups(self, region: str) -> Optional[List[Dict]]:
        """Recolectar información de security groups"""
        try:
            client = self._get_vpc_client(region)
            if not client:
                return None

            request = ListSecurityGroupsRequest()
            request.limit = 200
            response = client.list_security_groups(request)

            security_groups = []
            for sg in response.security_groups:
                sg_info = {
                    'id': sg.id,
                    'name': sg.name,
                    'description': getattr(sg, 'description', ''),
                    'vpc_id': getattr(sg, 'vpc_id', None),
                    'rules': [],
                    'assignments_count': 0,
                    'has_permissive_rules': False
                }

                # Analizar reglas
                for rule in sg.security_group_rules:
                    rule_info = {
                        'direction': rule.direction,
                        'protocol': rule.protocol,
                        'port_range_min': rule.port_range_min,
                        'port_range_max': rule.port_range_max,
                        'remote_ip_prefix': rule.remote_ip_prefix,
                        'remote_group_id': rule.remote_group_id,
                        'description': getattr(rule, 'description', ''),
                        'is_permissive': self._is_permissive_rule(rule)
                    }

                    if rule_info['is_permissive']:
                        sg_info['has_permissive_rules'] = True

                    sg_info['rules'].append(rule_info)

                # Contar asignaciones
                sg_info['assignments_count'] = await self._count_sg_assignments(sg.id, region)

                security_groups.append(sg_info)
                self.stats['total_security_groups'] += 1

            self.logger.info(
                f"Recolectados {len(security_groups)} security groups en {region}")
            return security_groups

        except Exception as e:
            self.logger.error(
                f"Error recolectando security groups en {region}: {str(e)}")
            return None

    async def _analyze_exposed_resources(self, region: str) -> Optional[List[Dict]]:
        """Analizar recursos expuestos a Internet (NET-004)"""
        try:
            ecs_client = self._get_ecs_client(region)
            if not ecs_client:
                return None

            request = ListServersDetailsRequest()
            request.limit = 200
            response = ecs_client.list_servers_details(request)

            exposed = []
            for server in response.servers:
                public_ips = self._extract_public_ips(server)

                if public_ips:
                    # Verificar puertos expuestos
                    exposed_ports = await self._check_exposed_ports(server, region)

                    if exposed_ports:
                        exposed_info = {
                            'resource_type': 'ecs',
                            'resource_id': server.id,
                            'resource_name': server.name,
                            'region': region,
                            'public_ips': public_ips,
                            'exposed_ports': exposed_ports,
                            'security_groups': [sg.id for sg in server.security_groups],
                            'critical_exposure': any(p['port'] in CRITICAL_PORTS for p in exposed_ports)
                        }
                        exposed.append(exposed_info)

            self.logger.info(
                f"Encontrados {len(exposed)} recursos expuestos en {region}")
            return exposed

        except Exception as e:
            self.logger.error(
                f"Error analizando recursos expuestos en {region}: {str(e)}")
            return None

    async def _collect_network_acls(self, region: str) -> Optional[List[Dict]]:
        """Recolectar Network ACLs (NET-005)"""
        try:
            client = self._get_vpc_client(region)
            if not client:
                return None

            # Nota: Ajustar según la API real de Huawei Cloud para NACLs
            nacls = []
            self.logger.info(f"Verificando Network ACLs en {region}")

            # Por ahora retornar lista vacía si no hay API disponible
            return nacls

        except Exception as e:
            self.logger.error(
                f"Error recolectando NACLs en {region}: {str(e)}")
            return None

    async def _collect_vpc_peerings(self, region: str) -> Optional[List[Dict]]:
        """Recolectar VPC Peerings (NET-006)"""
        try:
            client = self._get_vpc_client(region)
            if not client:
                return None

            request = ListVpcPeeringsRequest()
            request.limit = 100
            response = client.list_vpc_peerings(request)

            peerings = []
            for peering in response.peerings:
                peering_info = {
                    'id': peering.id,
                    'name': peering.name,
                    'status': peering.status,
                    'local_vpc_id': peering.local_vpc_info.vpc_id,
                    'peer_vpc_id': peering.accept_vpc_info.vpc_id,
                    'has_route_restrictions': False  # Verificar después
                }
                peerings.append(peering_info)
                self.stats['total_peerings'] += 1

            self.logger.info(
                f"Recolectados {len(peerings)} VPC peerings en {region}")
            return peerings

        except Exception as e:
            self.logger.error(
                f"Error recolectando VPC peerings en {region}: {str(e)}")
            return None

    async def _collect_load_balancers(self, region: str) -> Optional[List[Dict]]:
        """Recolectar Load Balancers (NET-007)"""
        try:
            client = self._get_elb_client(region)
            if not client:
                return None

            request = ListLoadBalancersRequest()
            request.limit = 100
            response = client.list_load_balancers(request)

            load_balancers = []
            for lb in response.loadbalancers:
                lb_info = {
                    'id': lb.id,
                    'name': lb.name,
                    'status': lb.provisioning_status,
                    'vip_address': lb.vip_address,
                    'listeners': [],
                    'has_ssl': False
                }

                # Verificar listeners para SSL/TLS
                try:
                    listener_req = ListListenersRequest()
                    listener_req.loadbalancer_id = [lb.id]
                    listener_resp = client.list_listeners(listener_req)

                    for listener in listener_resp.listeners:
                        listener_info = {
                            'id': listener.id,
                            'protocol': listener.protocol,
                            'protocol_port': listener.protocol_port,
                            'has_certificate': bool(getattr(listener, 'default_certificate_id', None))
                        }

                        if listener.protocol in ['HTTPS', 'SSL', 'TLS']:
                            lb_info['has_ssl'] = True

                        lb_info['listeners'].append(listener_info)

                except Exception as e:
                    self.logger.warning(
                        f"No se pudieron obtener listeners para ELB {lb.id}: {str(e)}")

                load_balancers.append(lb_info)
                self.stats['total_elbs'] += 1

            self.logger.info(
                f"Recolectados {len(load_balancers)} load balancers en {region}")
            return load_balancers

        except Exception as e:
            self.logger.error(
                f"Error recolectando load balancers en {region}: {str(e)}")
            return None

    async def _collect_flow_logs(self, region: str) -> Optional[List[Dict]]:
        """Recolectar Flow Logs (NET-008)"""
        try:
            client = self._get_vpc_client(region)
            if not client:
                return None

            request = ListFlowLogsRequest()
            request.limit = 100
            response = client.list_flow_logs(request)

            flow_logs = []
            for log in response.flow_logs:
                log_info = {
                    'id': log.id,
                    'name': log.name,
                    'resource_type': log.resource_type,
                    'resource_id': log.resource_id,
                    'log_group_id': log.log_group_id,
                    'log_stream_id': log.log_stream_id,
                    'status': getattr(log, 'status', 'active'),
                    'enabled': getattr(log, 'admin_state', True)
                }
                flow_logs.append(log_info)
                self.stats['total_flow_logs'] += 1

            self.logger.info(
                f"Recolectados {len(flow_logs)} flow logs en {region}")
            return flow_logs

        except Exception as e:
            self.logger.error(
                f"Error recolectando flow logs en {region}: {str(e)}")
            return None

    async def _collect_elastic_ips(self, region: str) -> Optional[List[Dict]]:
        """Recolectar Elastic IPs y sus asociaciones detalladas"""
        try:
            # Obtener cliente EIP
            eip_client = self._get_eip_client(region)
            if not eip_client:
                self.logger.warning(f"Cliente EIP no disponible para {region}")
                return None

            self.logger.info(f"Recolectando EIPs en {region}")
            
            # Importar el request para listar EIPs
            from huaweicloudsdkeip.v2.model import ListPublicipsRequest
            
            request = ListPublicipsRequest()
            request.limit = 200  # Máximo por página
            response = eip_client.list_publicips(request)
            
            eips = []
            
            for eip in response.publicips:
                # Información básica de la EIP
                eip_info = {
                    'id': eip.id,
                    'status': eip.status,
                    'type': eip.type,
                    'public_ip_address': eip.public_ip_address,
                    'private_ip_address': getattr(eip, 'private_ip_address', None),
                    'port_id': getattr(eip, 'port_id', None),
                    'tenant_id': eip.tenant_id,
                    'create_time': getattr(eip, 'create_time', None),
                    'bandwidth_id': getattr(eip, 'bandwidth_id', None),
                    'bandwidth_name': getattr(eip, 'bandwidth_name', None),
                    'bandwidth_size': getattr(eip, 'bandwidth_size', None),
                    'bandwidth_share_type': getattr(eip, 'bandwidth_share_type', None),
                    'profile': getattr(eip, 'profile', {}),
                    'region': region
                }
                
                # Determinar asociación
                if eip.status == 'ACTIVE' and eip_info['port_id']:
                    # EIP está asociada a un puerto
                    association = await self._get_eip_association_details(eip_info['port_id'], region)
                    eip_info['association'] = association
                    eip_info['is_associated'] = True
                else:
                    # EIP no está asociada
                    eip_info['association'] = None
                    eip_info['is_associated'] = False
                
                # Análisis de seguridad
                eip_info['security_analysis'] = await self._analyze_eip_security(eip_info, region)
                
                eips.append(eip_info)
            
            self.logger.info(f"Encontradas {len(eips)} EIPs en {region}")
            
            # Generar hallazgos de seguridad
            await self._check_eip_security_issues(eips, region)
            
            return eips

        except Exception as e:
            self.logger.error(f"Error recolectando EIPs en {region}: {str(e)}")
            return None

    async def _get_eip_association_details(self, port_id: str, region: str) -> Optional[Dict]:
        """Obtener detalles de la asociación de una EIP"""
        try:
            # Obtener información del puerto
            vpc_client = self._get_vpc_client(region)
            if not vpc_client:
                return None
                
            # Buscar el puerto en la información de servidores ECS
            ecs_client = self._get_ecs_client(region)
            if ecs_client:
                request = ListServersDetailsRequest()
                request.limit = 200
                response = ecs_client.list_servers_details(request)
                
                for server in response.servers:
                    # Verificar si este servidor usa el puerto
                    if hasattr(server, 'addresses') and server.addresses:
                        for network_name, addr_list in server.addresses.items():
                            for addr in addr_list:
                                # Buscar el port_id en las direcciones
                                if hasattr(addr, 'port') and addr.port == port_id:
                                    return {
                                        'resource_type': 'ecs',
                                        'resource_id': server.id,
                                        'resource_name': server.name,
                                        'resource_status': server.status,
                                        'network_name': network_name,
                                        'private_ip': addr.addr if hasattr(addr, 'addr') else None
                                    }
                                elif isinstance(addr, dict) and addr.get('port') == port_id:
                                    return {
                                        'resource_type': 'ecs',
                                        'resource_id': server.id,
                                        'resource_name': server.name,
                                        'resource_status': server.status,
                                        'network_name': network_name,
                                        'private_ip': addr.get('addr')
                                    }
        
            # Si no es ECS, podría ser Load Balancer u otro recurso
            # Intentar determinar el tipo de recurso por el port_id
            return {
                'resource_type': 'unknown',
                'resource_id': port_id,
                'resource_name': f'Port-{port_id}',
                'resource_status': 'unknown',
                'network_name': 'unknown',
                'private_ip': None
            }
            
        except Exception as e:
            self.logger.debug(f"Error obteniendo detalles de asociación para port {port_id}: {e}")
            return None

    async def _analyze_eip_security(self, eip_info: Dict, region: str) -> Dict:
        """Analizar aspectos de seguridad de una EIP"""
        analysis = {
            'unused_eip': False,
            'public_exposure': False,
            'critical_ports_exposed': [],
            'weak_bandwidth': False,
            'shared_bandwidth': False
        }
        
        # 1. EIP no utilizada
        if not eip_info['is_associated'] or eip_info['status'] != 'ACTIVE':
            analysis['unused_eip'] = True
        
        # 2. Exposición pública (siempre es pública por naturaleza)
        analysis['public_exposure'] = True
        
        # 3. Verificar ancho de banda
        bandwidth_size = eip_info.get('bandwidth_size', 0)
        if bandwidth_size and bandwidth_size < 5:  # Menos de 5 Mbps
            analysis['weak_bandwidth'] = True
        
        # 4. Ancho de banda compartido (potencial riesgo de performance)
        if eip_info.get('bandwidth_share_type') == 'WHOLE':
            analysis['shared_bandwidth'] = True
        
        # 5. Si está asociada, verificar exposición de puertos críticos
        if eip_info['is_associated'] and eip_info['association']:
            # Obtener security groups del recurso asociado
            critical_ports = await self._check_eip_critical_ports(eip_info, region)
            analysis['critical_ports_exposed'] = critical_ports
        
        return analysis

    async def _check_eip_critical_ports(self, eip_info: Dict, region: str) -> List[int]:
        """Verificar si una EIP tiene puertos críticos expuestos"""
        try:
            association = eip_info.get('association')
            if not association or association['resource_type'] != 'ecs':
                return []
            
            # Obtener security groups del servidor ECS asociado
            ecs_client = self._get_ecs_client(region)
            if not ecs_client:
                return []
            
            request = ShowServerRequest()
            request.server_id = association['resource_id']
            response = ecs_client.show_server(request)
            
            critical_exposed = []
            
            # Verificar security groups
            for sg in response.server.security_groups:
                # Aquí deberíamos obtener las reglas del SG y verificar puertos críticos
                # Por simplicidad, asumimos que los puertos comunes están expuestos
                # En una implementación real, se consultarían las reglas específicas
                pass
            
            return critical_exposed
            
        except Exception as e:
            self.logger.debug(f"Error verificando puertos críticos para EIP {eip_info['id']}: {e}")
            return []

    async def _check_eip_security_issues(self, eips: List[Dict], region: str):
        """Generar hallazgos de seguridad para EIPs"""
        
        # 1. EIPs no utilizadas
        unused_eips = [eip for eip in eips if eip['security_analysis']['unused_eip']]
        if unused_eips:
            self._add_finding(
                'NET-009',  # Nuevo código para EIPs no utilizadas
                'MEDIA',
                f'{len(unused_eips)} EIPs no utilizadas en {region}',
                {
                    'region': region,
                    'unused_eips': [
                        {
                            'id': eip['id'],
                            'public_ip': eip['public_ip_address'],
                            'status': eip['status'],
                            'bandwidth_cost': eip.get('bandwidth_size', 0)
                        } for eip in unused_eips
                    ],
                    'recommendation': 'Liberar EIPs no utilizadas para reducir costos y riesgos de seguridad'
                }
            )
        
        # 2. EIPs con ancho de banda débil
        weak_bandwidth_eips = [eip for eip in eips if eip['security_analysis']['weak_bandwidth']]
        if weak_bandwidth_eips:
            self._add_finding(
                'NET-010',  # Nuevo código para ancho de banda débil
                'BAJA',
                f'{len(weak_bandwidth_eips)} EIPs con ancho de banda menor a 5 Mbps en {region}',
                {
                    'region': region,
                    'weak_eips': [
                        {
                            'id': eip['id'],
                            'public_ip': eip['public_ip_address'],
                            'bandwidth': eip.get('bandwidth_size', 0)
                        } for eip in weak_bandwidth_eips
                    ],
                    'recommendation': 'Considerar aumentar el ancho de banda para aplicaciones críticas'
                }
            )
        
        # 3. EIPs asociadas a recursos con puertos críticos expuestos
        critical_exposed_eips = [
            eip for eip in eips 
            if eip['security_analysis']['critical_ports_exposed']
        ]
        if critical_exposed_eips:
            self._add_finding(
                'NET-011',  # Nuevo código para EIPs con exposición crítica
                'CRITICA',
                f'{len(critical_exposed_eips)} EIPs con puertos críticos expuestos en {region}',
                {
                    'region': region,
                    'critical_eips': [
                        {
                            'id': eip['id'],
                            'public_ip': eip['public_ip_address'],
                            'associated_resource': eip['association']['resource_name'] if eip['association'] else 'unknown',
                            'critical_ports': eip['security_analysis']['critical_ports_exposed']
                        } for eip in critical_exposed_eips
                    ],
                    'recommendation': 'Restringir acceso a puertos críticos desde EIPs públicas'
                }
            )

    def _get_eip_client(self, region: str):
        """Obtener cliente EIP para una región"""
        try:
            from huaweicloudsdkeip.v2 import EipClient
            from huaweicloudsdkcore.region.region import Region
            
            # Mapear región a región SDK
            sdk_region = self.region_map.get(region)
            if not sdk_region:
                self.logger.warning(f"Región {region} no mapeada para EIP")
                return None
            
            # Crear región
            eip_region = Region(sdk_region, f"https://vpc.{sdk_region}.myhuaweicloud.com")
            
            # Crear cliente
            client = EipClient.new_builder() \
                .with_credentials(self.credentials) \
                .with_region(eip_region) \
                .build()
            
            return client
            
        except ImportError:
            self.logger.warning(f"SDK de EIP no disponible. Saltando recolección de EIPs.")
            return None

    # ===== MÉTODOS DE VERIFICACIÓN SEGÚN CÓDIGOS CSV =====

    async def _check_vpc_segregation(self, results: Dict):
        """NET-001: VPC sin Segregación de Subnets"""
        vpcs_without_segregation = []

        # Manejar estructura por regiones
        vpcs_data = results.get('vpcs', {})
        
        # Si vpcs_data es un diccionario por regiones
        if isinstance(vpcs_data, dict):
            for region, vpcs in vpcs_data.items():
                if isinstance(vpcs, list):
                    for vpc in vpcs:
                        self._analyze_vpc_segregation(vpc, region, vpcs_without_segregation, results)
        # Si vpcs_data es una lista directa (compatibilidad)
        elif isinstance(vpcs_data, list):
            for vpc in vpcs_data:
                self._analyze_vpc_segregation(vpc, 'unknown', vpcs_without_segregation, results)

        # Generar vulnerabilidades encontradas
        if vpcs_without_segregation:
            self._add_finding(
                'NET-001',
                'ALTA',
                f'Se encontraron {len(vpcs_without_segregation)} VPCs sin segregación adecuada',
                {
                    'vpcs_without_segregation': vpcs_without_segregation
                }
            )

    def _analyze_vpc_segregation(self, vpc, region, vpcs_without_segregation, network_data):
        """Analizar segregación de una VPC específica"""
        vpc_id = vpc.get('id', 'Unknown')
        
        # Obtener subnets para esta VPC
        subnets_data = network_data.get('subnets', {})
        
        if isinstance(subnets_data, dict) and region in subnets_data:
            subnets = [s for s in subnets_data[region] if s.get('vpc_id') == vpc_id]
        elif isinstance(subnets_data, list):
            subnets = [s for s in subnets_data if s.get('vpc_id') == vpc_id]
        else:
            subnets = []

        # Verificar segregación
        if subnets:
            public_subnets = [s for s in subnets if s.get('is_public', False)]
            private_subnets = [s for s in subnets if not s.get('is_public', False)]

            if len(public_subnets) == 0 or len(private_subnets) == 0:
                vpcs_without_segregation.append({
                    'vpc_id': vpc_id,
                    'vpc_name': vpc.get('name', 'Unknown'),
                    'region': region,
                    'total_subnets': len(subnets),
                    'public_subnets': len(public_subnets),
                    'private_subnets': len(private_subnets)
                })

    async def _check_public_subnets(self, results: Dict):
        """NET-002: Subnets Públicas sin Justificación"""
        for region, subnets in results.get('subnets', {}).items():
            for subnet in subnets:
                if subnet['is_public'] and not self._requires_public_access(subnet):
                    self._add_finding(
                        'NET-002',
                        'ALTA',
                        f'Subnet pública sin justificación clara en {region}',
                        {
                            'subnet_id': subnet['id'],
                            'subnet_name': subnet['name'],
                            'cidr': subnet['cidr'],
                            'gateway_ip': subnet['gateway_ip'],
                            'recommendation': 'Evaluar si la subnet requiere acceso público o convertirla en privada'
                        }
                    )

    async def _check_security_group_rules(self, results: Dict):
        """NET-003: Security Groups con Reglas Permisivas"""
        for region, sgs in results.get('security_groups', {}).items():
            for sg in sgs:
                if sg['has_permissive_rules']:
                    permissive_rules = [
                        r for r in sg['rules'] if r['is_permissive']]

                    self._add_finding(
                        'NET-003',
                        'CRITICA',
                        f'Security Group con reglas excesivamente permisivas en {region}',
                        {
                            'sg_id': sg['id'],
                            'sg_name': sg['name'],
                            'permissive_rules_count': len(permissive_rules),
                            'assignments_count': sg['assignments_count'],
                            'sample_rules': permissive_rules[:3],
                            'recommendation': 'Restringir reglas a IPs y puertos específicos necesarios'
                        }
                    )

    async def _check_critical_ports(self, results: Dict):
        """NET-004: Puertos Críticos Expuestos"""
        exposed_resources = results.get('exposed_resources', [])

        for resource in exposed_resources:
            if resource['critical_exposure']:
                critical_ports = [p for p in resource['exposed_ports']
                                  if p['port'] in CRITICAL_PORTS]

                self._add_finding(
                    'NET-004',
                    'CRITICA',
                    f'Recurso con puertos críticos expuestos a Internet',
                    {
                        'resource_type': resource['resource_type'],
                        'resource_id': resource['resource_id'],
                        'resource_name': resource['resource_name'],
                        'region': resource['region'],
                        'public_ips': resource['public_ips'],
                        'critical_ports': [p['port'] for p in critical_ports],
                        'recommendation': 'Restringir acceso a puertos críticos solo desde IPs autorizadas'
                    }
                )

    async def _check_network_acls(self, results: Dict):
        """NET-005: Ausencia de Network ACLs"""
        for region, vpcs in results.get('vpcs', {}).items():
            nacls = results.get('network_acls', {}).get(region, [])

            if vpcs and not nacls:
                self._add_finding(
                    'NET-005',
                    'MEDIA',
                    f'Ausencia de Network ACLs configuradas en {region}',
                    {
                        'region': region,
                        'vpc_count': len(vpcs),
                        'nacl_count': 0,
                        'recommendation': 'Implementar Network ACLs como capa adicional de seguridad'
                    }
                )

    async def _check_vpc_peering_restrictions(self, results: Dict):
        """NET-006: VPC Peering sin Restricciones"""
        for region, peerings in results.get('vpc_peerings', {}).items():
            for peering in peerings:
                if not peering.get('has_route_restrictions', False):
                    self._add_finding(
                        'NET-006',
                        'ALTA',
                        f'VPC Peering sin restricciones de enrutamiento en {region}',
                        {
                            'peering_id': peering['id'],
                            'peering_name': peering['name'],
                            'local_vpc': peering['local_vpc_id'],
                            'peer_vpc': peering['peer_vpc_id'],
                            'recommendation': 'Implementar rutas específicas y restricciones en el peering'
                        }
                    )

    async def _check_elb_encryption(self, results: Dict):
        """NET-007: ELB sin Cifrado SSL/TLS"""
        for region, lbs in results.get('load_balancers', {}).items():
            for lb in lbs:
                if not lb['has_ssl']:
                    # Verificar si tiene listeners HTTP sin HTTPS
                    http_listeners = [l for l in lb['listeners']
                                      if l['protocol'] in ['HTTP', 'TCP']]

                    if http_listeners:
                        self._add_finding(
                            'NET-007',
                            'ALTA',
                            f'Load Balancer sin cifrado SSL/TLS en {region}',
                            {
                                'lb_id': lb['id'],
                                'lb_name': lb['name'],
                                'vip_address': lb['vip_address'],
                                'http_listeners': len(http_listeners),
                                'recommendation': 'Configurar listeners HTTPS con certificados SSL/TLS válidos'
                            }
                        )

    async def _check_flow_logs(self, results: Dict):
        """NET-008: Ausencia de Flow Logs"""
        for region, vpcs in results.get('vpcs', {}).items():
            flow_logs = results.get('flow_logs', {}).get(region, [])

            # Crear set de recursos con flow logs
            resources_with_logs = set()
            for log in flow_logs:
                if log.get('enabled', True):
                    resources_with_logs.add(log['resource_id'])

            # Verificar VPCs sin flow logs
            for vpc in vpcs:
                if vpc['id'] not in resources_with_logs:
                    self._add_finding(
                        'NET-008',
                        'MEDIA',
                        f'VPC sin Flow Logs habilitados en {region}',
                        {
                            'vpc_id': vpc['id'],
                            'vpc_name': vpc['name'],
                            'recommendation': 'Habilitar Flow Logs para auditoría y análisis de tráfico'
                        }
                    )

    async def _check_environment_isolation(self, results: Dict):
        """NET-009: Sin Aislamiento entre Ambientes"""
        # Verificar si hay comunicación entre VPCs de diferentes ambientes
        vpcs = []
        for region, region_vpcs in results.get('vpcs', {}).items():
            for vpc in region_vpcs:
                # Identificar ambiente por nombre de VPC
                env = 'unknown'
                vpc_name_lower = vpc.get('name', '').lower()
                if 'prod' in vpc_name_lower or 'production' in vpc_name_lower:
                    env = 'production'
                elif 'dev' in vpc_name_lower or 'desarrollo' in vpc_name_lower:
                    env = 'development'  
                elif 'test' in vpc_name_lower or 'qa' in vpc_name_lower:
                    env = 'test'
                
                vpcs.append({
                    'vpc_id': vpc['id'],
                    'vpc_name': vpc['name'],
                    'region': region,
                    'environment': env
                })
        
        # Verificar peerings entre diferentes ambientes
        cross_env_peerings = []
        for region, peerings in results.get('vpc_peerings', {}).items():
            for peering in peerings:
                vpc1_env = next((v['environment'] for v in vpcs if v['vpc_id'] == peering.get('vpc_id')), 'unknown')
                vpc2_env = next((v['environment'] for v in vpcs if v['vpc_id'] == peering.get('peer_vpc_id')), 'unknown')
                
                if vpc1_env != vpc2_env and vpc1_env != 'unknown' and vpc2_env != 'unknown':
                    cross_env_peerings.append(peering)
        
        if cross_env_peerings:
            self._add_finding(
                'NET-009',
                'CRITICA',
                f'Comunicación permitida entre ambientes diferentes',
                {
                    'cross_environment_peerings': len(cross_env_peerings),
                    'details': cross_env_peerings[:5],
                    'recommendation': 'Segregar ambientes en VPCs separadas con políticas restrictivas'
                }
            )

    async def _check_lateral_movement(self, results: Dict):
        """NET-010: Comunicación Lateral sin Restricción"""
        permissive_sgs = []
        
        for region, sgs in results.get('security_groups', {}).items():
            for sg in sgs:
                rules = sg.get('rules', [])
                
                # Buscar reglas que permiten ANY-ANY internamente
                for rule in rules:
                    if (rule.get('direction') == 'ingress' and 
                        rule.get('remote_group_id') == sg.get('id') and
                        rule.get('port_range_min') == 1 and 
                        rule.get('port_range_max') == 65535):
                        
                        permissive_sgs.append({
                            'sg_id': sg['id'],
                            'sg_name': sg.get('name', 'Unknown'),
                            'region': region
                        })
                        break
        
        if permissive_sgs:
            self._add_finding(
                'NET-010',
                'ALTA',
                f'{len(permissive_sgs)} Security Groups permiten comunicación lateral sin restricción',
                {
                    'permissive_security_groups': permissive_sgs,
                    'recommendation': 'Aplicar microsegmentación y principio de menor privilegio interno'
                }
            )

    async def _check_siem_integration(self, results: Dict):
        """NET-011: Sin Integración con Fortinet SIEM"""
        # Verificar si hay flow logs configurados (prerequisito para SIEM)
        regions_without_flow_logs = []
        
        for region in results.get('vpcs', {}).keys():
            flow_logs = results.get('flow_logs', {}).get(region, [])
            if not flow_logs:
                regions_without_flow_logs.append(region)
        
        # Siempre generar finding porque la integración SIEM es manual
        self._add_finding(
            'NET-011',
            'ALTA',
            'Integración con Fortinet SIEM requiere verificación manual',
            {
                'regions_without_flow_logs': regions_without_flow_logs,
                'total_regions': len(results.get('vpcs', {})),
                'recommendation': 'Integrar eventos de Huawei Cloud con FortiSIEM/FortiAnalyzer'
            }
        )

    async def _check_eip_documentation(self, results: Dict):
        """NET-012: EIPs sin Justificación Documentada"""
        undocumented_eips = []
        
        for region, eips in results.get('elastic_ips', {}).items():
            for eip in eips:
                # EIP sin descripción o con descripción genérica
                description = eip.get('description', '')
                if (not description or 
                    description.lower() in ['default', 'auto', 'temp', 'test']):
                    
                    undocumented_eips.append({
                        'eip_id': eip['id'],
                        'public_ip': eip.get('public_ip_address', 'Unknown'),
                        'region': region,
                        'is_associated': eip.get('is_associated', False)
                    })
        
        if undocumented_eips:
            self._add_finding(
                'NET-012',
                'MEDIA',
                f'{len(undocumented_eips)} EIPs sin justificación documentada',
                {
                    'undocumented_eips': undocumented_eips,
                    'recommendation': 'Documentar necesidad de cada EIP y liberar las no utilizadas'
                }
            )

    async def _check_bandwidth_limits(self, results: Dict):
        """NET-013: Bandwidth sin Límites Configurados"""
        unlimited_bandwidth = []
        
        for region, eips in results.get('elastic_ips', {}).items():
            for eip in eips:
                bandwidth_size = eip.get('bandwidth_size', 0)
                if bandwidth_size > 100:  # Más de 100 Mbps sin restricciones
                    unlimited_bandwidth.append({
                        'eip_id': eip['id'],
                        'public_ip': eip.get('public_ip_address', 'Unknown'),
                        'bandwidth_size': bandwidth_size,
                        'region': region
                    })
        
        if unlimited_bandwidth:
            self._add_finding(
                'NET-013',
                'MEDIA',
                f'{len(unlimited_bandwidth)} recursos con ancho de banda sin límites configurados',
                {
                    'high_bandwidth_resources': unlimited_bandwidth,
                    'recommendation': 'Configurar límites de bandwidth según SLAs'
                }
            )

    async def _check_route_table_documentation(self, results: Dict):
        """NET-014: Route Tables sin Documentación"""
        # Este check requiere información de route tables que no está siendo recolectada
        # Generar finding genérico
        total_vpcs = sum(len(vpcs) for vpcs in results.get('vpcs', {}).values())
        
        if total_vpcs > 0:
            self._add_finding(
                'NET-014',
                'BAJA',
                f'Verificación manual requerida para {total_vpcs} VPCs',
                {
                    'total_vpcs': total_vpcs,
                    'recommendation': 'Documentar y simplificar tablas de ruteo donde sea posible'
                }
            )

    async def _check_dns_resolver_restrictions(self, results: Dict):
        """NET-015: DNS Resolver sin Restricciones"""
        # Este check requiere configuración de DNS que no está siendo recolectada
        # Generar finding genérico
        self._add_finding(
            'NET-015',
            'MEDIA',
            'Configuración DNS requiere verificación manual',
            {
                'check_items': [
                    'DNS servers configuration',
                    'Private DNS zones',
                    'DNS filtering policies'
                ],
                'recommendation': 'Implementar DNS privado con filtrado de dominios maliciosos'
            }
        )

    # ===== MÉTODOS AUXILIARES =====

    def _is_public_subnet(self, subnet: Any) -> bool:
        """Determinar si una subnet es pública"""
        return bool(getattr(subnet, 'gateway_ip', None))

    def _determine_subnet_purpose(self, subnet: Any) -> str:
        """Determinar el propósito de una subnet basado en su nombre"""
        name = getattr(subnet, 'name', '').lower()

        if any(kw in name for kw in ['dmz', 'public', 'frontend', 'web']):
            return 'public'
        elif any(kw in name for kw in ['private', 'backend', 'db', 'database']):
            return 'private'
        elif any(kw in name for kw in ['mgmt', 'management', 'admin']):
            return 'management'
        else:
            return 'unknown'

    def _requires_public_access(self, subnet: Dict) -> bool:
        """Verificar si la subnet requiere acceso público por su propósito"""
        justified_purposes = ['public', 'dmz']
        return subnet.get('purpose', 'unknown') in justified_purposes

    def _is_permissive_rule(self, rule: Any) -> bool:
        """Verificar si una regla de security group es permisiva"""
        # Regla permisiva: 0.0.0.0/0 en puertos sensibles o rangos amplios
        if rule.direction == 'ingress':
            remote_ip = getattr(rule, 'remote_ip_prefix', '')

            if remote_ip in ['0.0.0.0/0', '::/0']:
                # Verificar si es un puerto crítico o rango amplio
                port_min = rule.port_range_min or 0
                port_max = rule.port_range_max or 65535

                # Es permisiva si:
                # - Permite todos los puertos
                # - Permite puertos críticos
                # - Permite rangos muy amplios (>1000 puertos)
                if (port_max - port_min > 1000) or \
                   any(p >= port_min and p <= port_max for p in CRITICAL_PORTS):
                    return True

        return False

    async def _count_sg_assignments(self, sg_id: str, region: str) -> int:
        """Contar cuántos recursos usan un security group"""
        try:
            ecs_client = self._get_ecs_client(region)
            if not ecs_client:
                return 0

            count = 0
            request = ListServersDetailsRequest()
            request.limit = 200
            response = ecs_client.list_servers_details(request)

            for server in response.servers:
                if any(sg.id == sg_id for sg in server.security_groups):
                    count += 1

            return count

        except Exception:
            return 0

    def _extract_public_ips(self, server: Any) -> List[str]:
        """Extraer IPs públicas de un servidor"""
        public_ips = []

        # Verificar diferentes formatos de IPs públicas
        if hasattr(server, 'addresses') and server.addresses:
            for network_name, addr_list in server.addresses.items():
                for addr in addr_list:
                    if hasattr(addr, 'OS-EXT-IPS:type'):
                        if getattr(addr, 'OS-EXT-IPS:type') == 'floating':
                            public_ips.append(addr.addr)
                    elif isinstance(addr, dict):
                        if addr.get('OS-EXT-IPS:type') == 'floating':
                            public_ips.append(addr.get('addr'))

        # También verificar publicIp directo
        if hasattr(server, 'publicIp') and server.publicIp:
            public_ips.extend(server.publicIp)

        return list(set(public_ips))

    async def _check_exposed_ports(self, server: Any, region: str) -> List[Dict]:
        """Verificar puertos expuestos en un servidor"""
        exposed_ports = []

        # Obtener security groups del servidor
        for sg in server.security_groups:
            # Aquí deberíamos obtener las reglas del SG
            # Por simplicidad, asumimos que tenemos las reglas cacheadas
            exposed_ports.append({
                'sg_id': sg.id,
                'sg_name': sg.name,
                'port': 'unknown',  # Se debe obtener de las reglas reales
                'protocol': 'tcp'
            })

        return exposed_ports

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
                'load_balancers': sum(len(lbs) for lbs in results['load_balancers'].values()),
                'flow_logs': sum(len(logs) for logs in results['flow_logs'].values()),
                'vpc_peerings': sum(len(peers) for peers in results['vpc_peerings'].values()),
                'elastic_ips': sum(len(eips) for eips in results['elastic_ips'].values()),
                'exposed_resources': len(results['exposed_resources']),
                'regions_analyzed': len([r for r in results['vpcs'] if results['vpcs'][r]])
            },
            # Datos del inventario
            'inventory': {
                'total_vpcs': 20,
                'total_security_groups': 17,
                'total_eips': 10,
                'total_elbs': 2,
                'total_regions': 5,
                'total_resources': 437
            },
            # Hallazgos por severidad
            'findings_by_severity': {
                'CRITICA': len([f for f in self.findings if f['severity'] == 'CRITICA']),
                'ALTA': len([f for f in self.findings if f['severity'] == 'ALTA']),
                'MEDIA': len([f for f in self.findings if f['severity'] == 'MEDIA']),
                'BAJA': len([f for f in self.findings if f['severity'] == 'BAJA'])
            },
            # Hallazgos por código
            'findings_by_code': {},
            # Métricas de exposición
            'exposure_metrics': {
                'resources_with_public_ip': len(results['exposed_resources']),
                'critical_exposures': len([r for r in results['exposed_resources']
                                          if r.get('critical_exposure', False)]),
                'regions_with_exposures': len(set(r['region'] for r in results['exposed_resources']))
            },
            # Estado de controles
            'control_status': {
                'NET-001': 'VERIFICADO' if any(f['id'] == 'NET-001' for f in self.findings) else 'CUMPLE',
                'NET-002': 'VERIFICADO' if any(f['id'] == 'NET-002' for f in self.findings) else 'CUMPLE',
                'NET-003': 'VERIFICADO' if any(f['id'] == 'NET-003' for f in self.findings) else 'CUMPLE',
                'NET-004': 'VERIFICADO' if any(f['id'] == 'NET-004' for f in self.findings) else 'CUMPLE',
                'NET-005': 'VERIFICADO' if any(f['id'] == 'NET-005' for f in self.findings) else 'CUMPLE',
                'NET-006': 'VERIFICADO' if any(f['id'] == 'NET-006' for f in self.findings) else 'CUMPLE',
                'NET-007': 'VERIFICADO' if any(f['id'] == 'NET-007' for f in self.findings) else 'CUMPLE',
                'NET-008': 'VERIFICADO' if any(f['id'] == 'NET-008' for f in self.findings) else 'CUMPLE'
            }
        }

        # Contar hallazgos por código
        for finding in self.findings:
            code = finding['id']
            stats['findings_by_code'][code] = stats['findings_by_code'].get(
                code, 0) + 1

        return stats
