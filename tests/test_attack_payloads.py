"""Test suite for attack payload detection.

This module tests various attack payloads including:
SQL Injection, XSS, LFI, Command Injection, Directory Traversal.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from rule_engine import RuleEngine
from request_processor import RequestProcessor


class TestAttackPayloads(unittest.TestCase):
    """Test cases for attack payload detection"""

    def setUp(self):
        """Set up test fixtures"""
        self.rule_engine = RuleEngine()
        self.processor = RequestProcessor()

    def test_sql_injection_single_quote(self):
        """Test SQL injection with single quote"""
        payload = "' OR '1'='1"
        result = self.rule_engine.check_sql_injection(payload)
        self.assertTrue(result['detected'])

    def test_sql_injection_union_select(self):
        """Test UNION-based SQL injection"""
        payload = "1 UNION SELECT NULL,NULL,NULL--"
        result = self.rule_engine.check_sql_injection(payload)
        self.assertTrue(result['detected'])

    def test_xss_script_tag(self):
        """Test XSS with script tag"""
        payload = "<script>alert('XSS')</script>"
        result = self.rule_engine.check_xss(payload)
        self.assertTrue(result['detected'])

    def test_xss_event_handler(self):
        """Test XSS with event handler"""
        payload = "<img src=x onerror=alert('XSS')>"
        result = self.rule_engine.check_xss(payload)
        self.assertTrue(result['detected'])

    def test_lfi_path_traversal(self):
        """Test LFI with path traversal"""
        payload = "../../../etc/passwd"
        result = self.rule_engine.check_lfi(payload)
        self.assertTrue(result['detected'])

    def test_command_injection_semicolon(self):
        """Test command injection with semicolon"""
        payload = "ping; cat /etc/passwd"
        result = self.rule_engine.check_command_injection(payload)
        self.assertTrue(result['detected'])

    def test_command_injection_pipe(self):
        """Test command injection with pipe"""
        payload = "ping example.com | ls -la"
        result = self.rule_engine.check_command_injection(payload)
        self.assertTrue(result['detected'])

    def test_directory_traversal_dotdot(self):
        """Test directory traversal"""
        payload = "../../etc/passwd"
        result = self.rule_engine.check_directory_traversal(payload)
        self.assertTrue(result['detected'])


if __name__ == '__main__':
    unittest.main()
