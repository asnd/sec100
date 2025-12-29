import requests
import json
import yaml
from typing import Dict, List, Optional
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings if SSL verification is disabled
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class VropsClient:
    """
    A client to interact with vROPS (Aria Operations) REST API
    """
    
    def __init__(self, hostname: str, username: str, password: str, port: int = 443, 
                 ssl_verify: bool = True, api_version: str = "6.8"):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.ssl_verify = ssl_verify
        self.api_version = api_version
        self.base_url = f"https://{hostname}:{port}/suite-api"
        self.session = requests.Session()
        self.token = None
        
    def authenticate(self) -> bool:
        """
        Authenticate with vROPS and get an authentication token
        """
        auth_url = f"{self.base_url}/api/auth/token/acquire"
        
        auth_data = {
            "username": self.username,
            "password": self.password
        }
        
        try:
            response = self.session.post(
                auth_url,
                json=auth_data,
                verify=self.ssl_verify
            )
            response.raise_for_status()
            
            auth_result = response.json()
            self.token = auth_result.get('token')
            
            # Set the token in the session headers
            self.session.headers.update({
                'Authorization': f'vRealizeOpsToken {self.token}'
            })
            
            return True
            
        except requests.exceptions.RequestException as e:
            print(f"Authentication failed: {str(e)}")
            return False
    
    def get_resources_by_adapter_kind(self, adapter_kind: str) -> List[Dict]:
        """
        Get resources by adapter kind
        """
        resources_url = f"{self.base_url}/api/resources"
        
        params = {
            'adapterKind': adapter_kind
        }
        
        try:
            response = self.session.get(
                resources_url,
                params=params,
                verify=self.ssl_verify
            )
            response.raise_for_status()
            
            return response.json().get('resourceList', [])
            
        except requests.exceptions.RequestException as e:
            print(f"Failed to get resources for adapter kind {adapter_kind}: {str(e)}")
            return []
    
    def get_resources_by_resource_kind(self, resource_kind: str) -> List[Dict]:
        """
        Get resources by resource kind
        """
        resources_url = f"{self.base_url}/api/resources"
        
        params = {
            'resourceKind': resource_kind
        }
        
        try:
            response = self.session.get(
                resources_url,
                params=params,
                verify=self.ssl_verify
            )
            response.raise_for_status()
            
            return response.json().get('resourceList', [])
            
        except requests.exceptions.RequestException as e:
            print(f"Failed to get resources for resource kind {resource_kind}: {str(e)}")
            return []
    
    def get_resource_properties(self, resource_id: str, property_keys: List[str]) -> Dict:
        """
        Get specific properties for a resource
        """
        properties_url = f"{self.base_url}/api/resources/{resource_id}/properties"
        
        params = {
            'propertyKeys': property_keys
        }
        
        try:
            response = self.session.get(
                properties_url,
                params={'propertyKeys': property_keys},
                verify=self.ssl_verify
            )
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            print(f"Failed to get properties for resource {resource_id}: {str(e)}")
            return {}
    
    def get_all_resources(self) -> List[Dict]:
        """
        Get all resources in vROPS
        """
        resources_url = f"{self.base_url}/api/resources"
        
        try:
            response = self.session.get(
                resources_url,
                verify=self.ssl_verify
            )
            response.raise_for_status()
            
            return response.json().get('resourceList', [])
            
        except requests.exceptions.RequestException as e:
            print(f"Failed to get all resources: {str(e)}")
            return []
    
    def get_clusters(self) -> List[Dict]:
        """
        Get VMware clusters from vROPS
        Resource kind: ClusterComputeResource
        """
        return self.get_resources_by_resource_kind('ClusterComputeResource')
    
    def get_nsx_t_managers(self) -> List[Dict]:
        """
        Get NSX-T managers from vROPS
        """
        # Different possible resource kinds for NSX-T managers
        nsx_managers = []
        nsx_managers.extend(self.get_resources_by_resource_kind('NSX Manager'))
        nsx_managers.extend(self.get_resources_by_adapter_kind('NSXAdapter'))
        return nsx_managers
    
    def get_nsx_t_edge_nodes(self) -> List[Dict]:
        """
        Get NSX-T edge nodes from vROPS
        """
        # Resource kind for NSX-T edge nodes
        return self.get_resources_by_resource_kind('NetworkEdge')
    
    def close(self):
        """
        Close the session and revoke the token
        """
        if self.token:
            try:
                revoke_url = f"{self.base_url}/api/auth/token"
                self.session.delete(revoke_url, verify=self.ssl_verify)
            except:
                pass  # Ignore errors during token revocation
        
        self.session.close()


def load_config(config_path: str) -> Dict:
    """
    Load configuration from YAML file
    """
    with open(config_path, 'r') as file:
        return yaml.safe_load(file)


if __name__ == "__main__":
    # Example usage
    config = load_config('../config/config.yaml')
    
    client = VropsClient(
        hostname=config['vrops']['hostname'],
        username=config['vrops']['username'],
        password=config['vrops']['password'],
        port=config['vrops'].get('port', 443),
        ssl_verify=config['vrops'].get('ssl_verify', True),
        api_version=config['vrops'].get('api_version', '6.8')
    )
    
    if client.authenticate():
        print("Authentication successful")
        
        clusters = client.get_clusters()
        print(f"Found {len(clusters)} clusters")
        
        nsx_managers = client.get_nsx_t_managers()
        print(f"Found {len(nsx_managers)} NSX-T managers")
        
        nsx_edges = client.get_nsx_t_edge_nodes()
        print(f"Found {len(nsx_edges)} NSX-T edge nodes")
        
        client.close()
    else:
        print("Authentication failed")