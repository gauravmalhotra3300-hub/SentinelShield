#!/usr/bin/env python3
"""
SentinelShield WAF Engine - Main Web Application Firewall Implementation
Author: Gaurav Malhotra
Version: 1.0.0

This module implements the core WAF engine that orchestrates all components:
- Request processing
- Threat detection
- Rate limiting
- Alert generation
- Logging
"""

import json
import logging
import os
from datetime import datetime
from flask import Flask, request, jsonify
from request_processor import RequestProcessor
from rule_engine import RuleEngine
from traffic_analyzer import TrafficAnalyzer
from alert_generator import AlertGenerator
from logger import EventLogger

# Initialize Flask application
app = Flask(__name__)

# Initialize WAF components
request_processor = RequestProcessor()
rule_engine = RuleEngine()
traffic_analyzer = TrafficAnalyzer()
alert_generator = AlertGenerator()
event_logger = EventLogger()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# WAF Configuration
WAF_CONFIG = {
    "enabled": True,
    "listen_port": 5000,
    "request_timeout": 30,
    "max_content_length": 16 * 1024 * 1024,  # 16MB
    "rate_limit": {
        "requests_per_minute": 100,
        "window_size_seconds": 60
    }
}

class WAFEngine:
    """Main WAF Engine orchestrator"""
    
    def __init__(self):
        self.config = WAF_CONFIG
        self.enabled = self.config["enabled"]
        self.request_count = 0
        self.blocked_count = 0
        self.alert_count = 0
        
    def process_request(self, http_request):
        """
        Process incoming HTTP request through all WAF components
        
        Args:
            http_request: Flask request object
            
        Returns:
            Decision object with allow/block status and alert info
        """
        self.request_count += 1
        
        # Step 1: Parse request
        try:
            parsed_request = request_processor.parse(http_request)
        except Exception as e:
            logger.error(f"Request parsing failed: {str(e)}")
            return self._create_response(allow=False, reason="PARSING_ERROR")
        
        # Step 2: Analyze traffic behavior
        client_ip = request.remote_addr
        traffic_result = traffic_analyzer.analyze(
            ip_address=client_ip,
            request=parsed_request
        )
        
        if traffic_result["blocked"]:
            self._log_event({
                "type": "RATE_LIMIT_VIOLATION",
                "ip": client_ip,
                "reason": traffic_result["reason"],
                "requests_count": traffic_result.get("requests_count", 0)
            })
            self.blocked_count += 1
            return self._create_response(allow=False, reason="RATE_LIMIT_EXCEEDED")
        
        # Step 3: Check for attack signatures
        detection_result = rule_engine.detect_threats(parsed_request)
        
        if detection_result["threat_detected"]:
            # Step 4: Generate alert
            alert = alert_generator.generate_alert(
                threat_type=detection_result["threat_type"],
                severity=detection_result["severity"],
                client_ip=client_ip,
                request=parsed_request
            )
            
            # Log the attack
            self._log_event({
                "type": "THREAT_DETECTED",
                "threat_category": detection_result["threat_type"],
                "severity": detection_result["severity"],
                "ip": client_ip,
                "payload": parsed_request.get("suspicious_payload", "")
            })
            
            self.blocked_count += 1
            self.alert_count += 1
            
            # Decide whether to block or allow
            if alert.get("action", "BLOCK") == "BLOCK":
                return self._create_response(
                    allow=False,
                    reason=f"THREAT_DETECTED: {detection_result['threat_type']}",
                    alert=alert
                )
        
        # Request passed all checks
        self._log_event({
            "type": "REQUEST_ALLOWED",
            "ip": client_ip,
            "method": parsed_request.get("method", "UNKNOWN"),
            "path": parsed_request.get("path", "/")
        })
        
        return self._create_response(allow=True)
    
    def _create_response(self, allow, reason="OK", alert=None):
        """Create standardized response object"""
        return {
            "allow": allow,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat(),
            "alert": alert
        }
    
    def _log_event(self, event):
        """Log security event"""
        event["timestamp"] = datetime.utcnow().isoformat()
        event["request_number"] = self.request_count
        event_logger.log(event)
    
    def get_statistics(self):
        """Return WAF statistics"""
        return {
            "total_requests": self.request_count,
            "blocked_requests": self.blocked_count,
            "alerts_generated": self.alert_count,
            "allow_rate": round((self.request_count - self.blocked_count) / self.request_count * 100, 2) if self.request_count > 0 else 0
        }

# Initialize WAF Engine
waf = WAFEngine()

@app.route('/test', methods=['GET', 'POST'])
def test_endpoint():
    """Main testing endpoint"""
        try:
            decision = waf.process_request(request)
            if decision["allow"]:
                return jsonify({"status": "allowed", "message": "Request passed WAF inspection"}), 200
            else:
                return jsonify({
                    "status": "blocked",
                    "reason": decision["reason"],
                    "timestamp": decision["timestamp"]
                }), 403
        except Exception as e:
            logger.error(f"Error in /test endpoint: {str(e)}")
            return jsonify({"error": "Request processing error", "details": str(e)}), 500

@app.route('/stats', methods=['GET'])
def statistics():
    """Return WAF statistics"""
    return jsonify(waf.get_statistics()), 200

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "waf_enabled": waf.enabled}), 200

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not Found"}), 404

@app.errorhandler(500)
def server_error(error):
    logger.error(f"Server error: {str(error)}")
    return jsonify({"error": "Internal Server Error"}), 500

if __name__ == '__main__':
    port = WAF_CONFIG["listen_port"]
    logger.info(f"Starting SentinelShield WAF on port {port}")
    logger.info(f"WAF Status: {'ENABLED' if waf.enabled else 'DISABLED'}")
    
    app.run(
        host='localhost',
        port=port,
        debug=False,
        use_reloader=False
    )
