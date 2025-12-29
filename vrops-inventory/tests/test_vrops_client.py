import unittest
from unittest.mock import Mock, patch
from src.vrops_client import VropsClient


class TestVropsClient(unittest.TestCase):
    """
    Test cases for VropsClient
    """
    
    def setUp(self):
        self.client = VropsClient(
            hostname='test-vrops.example.com',
            username='test-user',
            password='test-password'
        )
    
    @patch('src.vrops_client.requests.Session.post')
    def test_authenticate_success(self, mock_post):
        # Mock successful authentication response
        mock_response = Mock()
        mock_response.json.return_value = {'token': 'test-token'}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        
        result = self.client.authenticate()
        
        self.assertTrue(result)
        self.assertEqual(self.client.token, 'test-token')
    
    @patch('src.vrops_client.requests.Session.get')
    def test_get_clusters(self, mock_get):
        # Mock successful clusters response
        mock_response = Mock()
        mock_response.json.return_value = {
            'resourceList': [
                {
                    'identifier': 'cluster-1',
                    'resourceKey': {'name': 'TestCluster1'}
                }
            ]
        }
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response
        
        clusters = self.client.get_clusters()
        
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]['resourceKey']['name'], 'TestCluster1')


if __name__ == '__main__':
    unittest.main()