# Usage Examples for vROPS Inventory Generator

## Basic Usage

### Command Line Usage
```bash
# Generate inventory with default config
python -m src.inventory_generator

# Generate inventory with custom config
python -m src.inventory_generator --config /path/to/config.yaml

# Generate inventory with custom output file
python -m src.inventory_generator --output /path/to/custom-inventory.json
```

## Python API Usage

### Simple Example
```python
from src.inventory_generator import InventoryGenerator

# Create generator with default config
generator = InventoryGenerator('../config/config.yaml')

# Authenticate with vROPS
if generator.vrops_client.authenticate():
    # Generate the inventory
    inventory = generator.generate_inventory()
    
    # Save to file
    generator.save_inventory('my-inventory.json')
    
    # Close the client connection
    generator.vrops_client.close()
```

### Advanced Example
```python
from src.vrops_client import VropsClient

# Create client directly
client = VropsClient(
    hostname='vrops.example.com',
    username='myuser',
    password='mypassword',
    port=443,
    ssl_verify=False  # Set to True in production
)

if client.authenticate():
    # Get specific resources
    clusters = client.get_clusters()
    nsx_managers = client.get_nsx_t_managers()
    nsx_edges = client.get_nsx_t_edge_nodes()
    
    print(f"Found {len(clusters)} clusters")
    print(f"Found {len(nsx_managers)} NSX-T managers")
    print(f"Found {len(nsx_edges)} NSX-T edge nodes")
    
    client.close()
```

## Sample Inventory Output

The generated inventory will look like this:

```json
{
  "all": {
    "children": [
      "clusters",
      "nsx_t_managers",
      "nsx_t_edge_nodes"
    ]
  },
  "_meta": {
    "hostvars": {
      "Cluster-1": {
        "vrops_resource_id": "domain-c123",
        "resource_kind": "ClusterComputeResource",
        "name": "Cluster-1"
      },
      "NSX-Manager-1": {
        "vrops_resource_id": "manager-123",
        "resource_kind": "NSX Manager",
        "name": "NSX-Manager-1"
      }
    }
  },
  "clusters": {
    "hosts": [
      "Cluster-1",
      "Cluster-2"
    ]
  },
  "nsx_t_managers": {
    "hosts": [
      "NSX-Manager-1"
    ]
  },
  "nsx_t_edge_nodes": {
    "hosts": [
      "Edge-Node-1",
      "Edge-Node-2"
    ]
  }
}
```

## Configuration File

Create a `config/config.yaml` file with your vROPS connection details:

```yaml
vrops:
  hostname: "vrops.example.com"
  username: "your-username"
  password: "your-password"
  port: 443
  ssl_verify: false  # Set to true in production
  api_version: "6.8"  # Adjust based on your vROPS version

# Inventory options
inventory:
  output_file: "inventory.json"
  include_clusters: true
  include_nsx_t_edge: true
  include_nsx_t_manager: true
```