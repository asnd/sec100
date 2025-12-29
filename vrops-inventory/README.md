# vROPS (Aria Operations) Inventory Generator

This Python tool connects to vROPS (Aria Operations) REST API to generate Ansible-compatible inventory files for VMware infrastructure components including clusters, NSX-T edge nodes, and NSX-T managers.

## Features

- Connect to vROPS REST API
- Retrieve information about clusters, NSX-T edge nodes, and NSX-T managers
- Generate dynamic Ansible inventory in JSON format
- Support for authentication via config file or environment variables

## Prerequisites

- Python 3.8+
- vROPS (Aria Operations) API access
- Appropriate credentials with read access to inventory data

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Create a `config/config.yaml` file with your vROPS connection details:

```yaml
vrops:
  hostname: "your-vrops-hostname"
  username: "your-username"
  password: "your-password"
  port: 443
  ssl_verify: false  # Set to true in production
```

## Usage

```bash
python -m src.inventory_generator
```

## Output

The tool generates an Ansible inventory file in JSON format with groups for:
- clusters
- nsx_t_edge_nodes
- nsx_t_managers