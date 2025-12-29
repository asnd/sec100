import json
import sys
from typing import Dict, List
from .vrops_client import VropsClient, load_config


class InventoryGenerator:
    """
    Generate Ansible-compatible inventory from vROPS data
    """
    
    def __init__(self, config_path: str):
        self.config = load_config(config_path)
        self.vrops_client = VropsClient(
            hostname=self.config['vrops']['hostname'],
            username=self.config['vrops']['username'],
            password=self.config['vrops']['password'],
            port=self.config['vrops'].get('port', 443),
            ssl_verify=self.config['vrops'].get('ssl_verify', True),
            api_version=self.config['vrops'].get('api_version', '6.8')
        )
    
    def generate_inventory(self) -> Dict:
        """
        Generate the complete Ansible inventory
        """
        # Initialize _meta as an instance variable
        self._meta = {
            'hostvars': {}
        }

        inventory = {
            '_meta': self._meta,
            'all': {
                'children': []
            }
        }

        # Add clusters group if enabled
        if self.config['inventory'].get('include_clusters', True):
            clusters = self.vrops_client.get_clusters()
            cluster_hosts = self._process_clusters(clusters)
            inventory['clusters'] = {
                'hosts': cluster_hosts
            }
            inventory['all']['children'].append('clusters')

        # Add NSX-T managers group if enabled
        if self.config['inventory'].get('include_nsx_t_manager', True):
            nsx_managers = self.vrops_client.get_nsx_t_managers()
            nsx_manager_hosts = self._process_nsx_managers(nsx_managers)
            inventory['nsx_t_managers'] = {
                'hosts': nsx_manager_hosts
            }
            inventory['all']['children'].append('nsx_t_managers')

        # Add NSX-T edge nodes group if enabled
        if self.config['inventory'].get('include_nsx_t_edge', True):
            nsx_edges = self.vrops_client.get_nsx_t_edge_nodes()
            nsx_edge_hosts = self._process_nsx_edges(nsx_edges)
            inventory['nsx_t_edge_nodes'] = {
                'hosts': nsx_edge_hosts
            }
            inventory['all']['children'].append('nsx_t_edge_nodes')

        return inventory
    
    def _process_clusters(self, clusters: List[Dict]) -> List[str]:
        """
        Process cluster data and return a list of hostnames/addresses
        """
        hosts = []
        for cluster in clusters:
            # Extract cluster name
            cluster_name = cluster.get('resourceKey', {}).get('name', 'unknown')
            resource_id = cluster.get('identifier', 'unknown')
            
            # For clusters, we might want to add additional properties
            # For now, we'll just use the resource name
            hosts.append(cluster_name)
            
            # Add hostvars for the cluster
            self._add_hostvars(cluster_name, {
                'vrops_resource_id': resource_id,
                'resource_kind': 'ClusterComputeResource',
                'name': cluster_name
            })
        
        return hosts
    
    def _process_nsx_managers(self, nsx_managers: List[Dict]) -> List[str]:
        """
        Process NSX-T manager data and return a list of hostnames/addresses
        """
        hosts = []
        for manager in nsx_managers:
            # Extract manager name
            manager_name = manager.get('resourceKey', {}).get('name', 'unknown')
            resource_id = manager.get('identifier', 'unknown')
            
            # Try to get the IP address or hostname from properties
            # This might require additional API call to get properties
            hosts.append(manager_name)
            
            # Add hostvars for the manager
            self._add_hostvars(manager_name, {
                'vrops_resource_id': resource_id,
                'resource_kind': 'NSX Manager',
                'name': manager_name
            })
        
        return hosts
    
    def _process_nsx_edges(self, nsx_edges: List[Dict]) -> List[str]:
        """
        Process NSX-T edge node data and return a list of hostnames/addresses
        """
        hosts = []
        for edge in nsx_edges:
            # Extract edge node name
            edge_name = edge.get('resourceKey', {}).get('name', 'unknown')
            resource_id = edge.get('identifier', 'unknown')
            
            # For edge nodes, we might want to get IP information
            hosts.append(edge_name)
            
            # Add hostvars for the edge node
            self._add_hostvars(edge_name, {
                'vrops_resource_id': resource_id,
                'resource_kind': 'NetworkEdge',
                'name': edge_name
            })
        
        return hosts
    
    def _add_hostvars(self, hostname: str, vars_dict: Dict):
        """
        Add variables for a specific host
        """
        if hostname not in self._meta['hostvars']:
            self._meta['hostvars'][hostname] = {}
        self._meta['hostvars'][hostname].update(vars_dict)
    
    def save_inventory(self, output_file: str = None):
        """
        Generate and save the inventory to a file
        """
        # Initialize _meta as an instance variable
        self._meta = {
            'hostvars': {}
        }
        
        inventory = self.generate_inventory()
        
        output_path = output_file or self.config['inventory'].get('output_file', 'inventory.json')
        
        with open(output_path, 'w') as f:
            json.dump(inventory, f, indent=2)
        
        print(f"Inventory saved to {output_path}")
        return inventory


def main():
    """
    Main function to run the inventory generator
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate Ansible inventory from vROPS')
    parser.add_argument('--config', '-c', default='../config/config.yaml', 
                        help='Path to configuration file')
    parser.add_argument('--output', '-o', default=None, 
                        help='Output file path (overrides config)')
    
    args = parser.parse_args()
    
    try:
        generator = InventoryGenerator(args.config)
        
        if generator.vrops_client.authenticate():
            print("Successfully authenticated with vROPS")
            inventory = generator.save_inventory(args.output)
            generator.vrops_client.close()
            print("Inventory generation completed successfully")
        else:
            print("Failed to authenticate with vROPS")
            sys.exit(1)
            
    except Exception as e:
        print(f"Error generating inventory: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()