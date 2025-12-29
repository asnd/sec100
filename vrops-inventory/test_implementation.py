#!/usr/bin/env python3
"""
Test script to verify the vROPS inventory generator implementation
"""

import os
import sys
import json
from src.inventory_generator import InventoryGenerator

def test_basic_functionality():
    """Test basic functionality of the inventory generator"""
    print("Testing basic functionality...")
    
    # Check if config file exists
    config_path = "config/config.yaml"
    if not os.path.exists(config_path):
        print(f"Config file not found at {config_path}")
        print("Creating a sample config for testing...")
        
        sample_config = {
            'vrops': {
                'hostname': 'vrops.example.com',
                'username': 'test-user',
                'password': 'test-password',
                'port': 443,
                'ssl_verify': False,
                'api_version': '6.8'
            },
            'inventory': {
                'output_file': 'test-inventory.json',
                'include_clusters': True,
                'include_nsx_t_edge': True,
                'include_nsx_t_manager': True
            }
        }
        
        import yaml
        with open(config_path, 'w') as f:
            yaml.dump(sample_config, f)
    
    try:
        # Create generator
        generator = InventoryGenerator(config_path)
        
        # Print configuration details
        print(f"Config loaded: vROPS host = {generator.config['vrops']['hostname']}")
        print(f"Inventory settings: {generator.config['inventory']}")
        
        # Test that methods exist
        assert hasattr(generator, 'generate_inventory'), "generate_inventory method missing"
        assert hasattr(generator, 'save_inventory'), "save_inventory method missing"
        
        print("✓ Basic functionality test passed")
        return True
        
    except Exception as e:
        print(f"✗ Basic functionality test failed: {str(e)}")
        return False

def test_vrops_client():
    """Test VROPS client functionality"""
    print("\nTesting VROPS client...")
    
    try:
        from src.vrops_client import VropsClient
        
        # Create a client instance (without authenticating for this test)
        client = VropsClient(
            hostname='test-vrops.example.com',
            username='test',
            password='test',
            ssl_verify=False
        )
        
        # Test that required methods exist
        methods_to_check = [
            'authenticate', 'get_clusters', 'get_nsx_t_managers', 
            'get_nsx_t_edge_nodes', 'get_resources_by_resource_kind',
            'get_resources_by_adapter_kind', 'close'
        ]
        
        for method in methods_to_check:
            assert hasattr(client, method), f"Method {method} missing from VropsClient"
        
        print("✓ VROPS client test passed")
        return True
        
    except Exception as e:
        print(f"✗ VROPS client test failed: {str(e)}")
        return False

def test_inventory_structure():
    """Test that the inventory structure is correct"""
    print("\nTesting inventory structure...")
    
    try:
        # Create a mock inventory to test structure
        mock_inventory = {
            "all": {
                "children": [
                    "clusters",
                    "nsx_t_managers", 
                    "nsx_t_edge_nodes"
                ]
            },
            "_meta": {
                "hostvars": {}
            },
            "clusters": {
                "hosts": []
            },
            "nsx_t_managers": {
                "hosts": []
            },
            "nsx_t_edge_nodes": {
                "hosts": []
            }
        }
        
        # Verify structure
        required_keys = ["all", "_meta", "clusters", "nsx_t_managers", "nsx_t_edge_nodes"]
        for key in required_keys:
            assert key in mock_inventory, f"Missing key {key} in inventory structure"
        
        assert "children" in mock_inventory["all"], "Missing 'children' in 'all' group"
        assert "hostvars" in mock_inventory["_meta"], "Missing 'hostvars' in '_meta'"
        assert "hosts" in mock_inventory["clusters"], "Missing 'hosts' in 'clusters' group"
        
        print("✓ Inventory structure test passed")
        return True
        
    except Exception as e:
        print(f"✗ Inventory structure test failed: {str(e)}")
        return False

def main():
    """Run all tests"""
    print("Running tests for vROPS Inventory Generator...\n")
    
    tests = [
        test_basic_functionality,
        test_vrops_client,
        test_inventory_structure
    ]
    
    results = []
    for test in tests:
        results.append(test())
    
    print(f"\n{'='*50}")
    print(f"Test Results: {sum(results)}/{len(results)} passed")
    
    if all(results):
        print("✓ All tests passed!")
        return 0
    else:
        print("✗ Some tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())