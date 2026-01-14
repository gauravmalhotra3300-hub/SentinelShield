"""Test suite for normal HTTP requests validation

This module contains test cases to verify that the WAF correctly
handles legitimate HTTP requests without blocking them.
"""

import unittest
import json
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from request_processor import RequestProcessor
from rule_engine import RuleEngine
from traffic_analyzer import TrafficAnalyzer


class TestNormalRequests(unittest.TestCase):
    """Test cases for normal request handling"""

    def setUp(self):
        """Set up test fixtures"""
        self.processor = RequestProcessor()
        self.rule_engine = RuleEngine()
        self.traffic_analyzer = TrafficAnalyzer()

    def test_get_request_simple(self):
        """Test simple GET request processing"""
        request = {
            'method': 'GET',
            'path': '/api/users',
            'headers': {'User-Agent': 'Mozilla/5.0'},
            'query_string': '',
            'body': ''
        }
        
        processed = self.processor.process(request)
        self.assertIsNotNone(processed)
        self.assertEqual(processed['method'], 'GET')

    def test_post_request_json_data(self):
        """Test POST request with JSON payload"""
        request = {
            'method': 'POST',
            'path': '/api/users',
            'headers': {'Content-Type': 'application/json'},
            'query_string': '',
            'body': json.dumps({'username': 'testuser', 'email': 'test@example.com'})
        }
        
        processed = self.processor.process(request)
        self.assertIsNotNone(processed)
        self.assertEqual(processed['method'], 'POST')

    def test_get_request_with_parameters(self):
        """Test GET request with URL parameters"""
        request = {
            'method': 'GET',
            'path': '/api/search',
            'headers': {},
            'query_string': 'q=python&limit=10',
            'body': ''
        }
        
        processed = self.processor.process(request)
        self.assertIsNotNone(processed)
        self.assertIn('q=python', processed.get('query_string', ''))

    def test_request_with_headers(self):
        """Test request with custom headers"""
        request = {
            'method': 'GET',
            'path': '/api/protected',
            'headers': {
                'Authorization': 'Bearer token123',
                'User-Agent': 'TestClient/1.0',
                'Accept': 'application/json'
            },
            'query_string': '',
            'body': ''
        }
        
        processed = self.processor.process(request)
        self.assertIsNotNone(processed)

    def test_rate_limiting_within_limit(self):
        """Test that legitimate requests within rate limits pass through"""
        for i in range(5):
            request = {
                'method': 'GET',
                'path': f'/api/resource/{i}',
                'ip': '192.168.1.100'
            }
            result = self.traffic_analyzer.analyze(request)
            self.assertTrue(result.get('allowed', True))

    def test_multiple_valid_requests(self):
        """Test processing multiple valid requests in sequence"""
        requests = [
            {'method': 'GET', 'path': '/'},
            {'method': 'GET', 'path': '/api'},
            {'method': 'POST', 'path': '/api/login', 'body': 'user=admin&pass=123'},
            {'method': 'GET', 'path': '/api/profile'},
        ]
        
        for req in requests:
            processed = self.processor.process(req)
            self.assertIsNotNone(processed)


if __name__ == '__main__':
    unittest.main()
