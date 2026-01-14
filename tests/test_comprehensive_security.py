"""Comprehensive security and rate limiting tests for WAF."""

import unittest
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from traffic_analyzer import TrafficAnalyzer
from waf_engine import WAFEngine

class TestRateLimiting(unittest.TestCase):
    def setUp(self):
        self.traffic_analyzer = TrafficAnalyzer()
    
    def test_rate_limit_detection(self):
        """Test rate limiting blocks excessive requests"""
        ip = "192.168.1.100"
        for i in range(150):
            request = {'ip': ip, 'timestamp': time.time()}
            result = self.traffic_analyzer.analyze(request)
            if i > 100:
                self.assertFalse(result.get('allowed', True))

class TestWAFIntegration(unittest.TestCase):
    def setUp(self):
        self.waf_engine = WAFEngine()
    
    def test_waf_processes_requests(self):
        """Test WAF engine processes requests"""
        request = {'method': 'GET', 'path': '/', 'headers': {}}
        result = self.waf_engine.process(request)
        self.assertIsNotNone(result)

if __name__ == '__main__':
    unittest.main()
