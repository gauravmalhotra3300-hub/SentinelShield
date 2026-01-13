import re
from typing import Dict, List, Tuple

class RuleEngine:
    """Rule-based threat detection engine"""
    
    def __init__(self):
        self.rules = self._initialize_rules()
    
    def _initialize_rules(self) -> List[Dict]:
        """Initialize attack detection rules"""
        return [
            {
                'name': 'SQL_INJECTION',
                'patterns': [
                    r"union.*select", r"union.*from", r"union.*where",
                    r"drop\s+table", r"delete\s+from", r"insert\s+into",
                    r"update\s+.*\s+set", r"or\s+1\s*=\s*1", r"'\s*or\s*'",
                    r"--\s*$", r"/\*.*\*/", r"xp_", r"sp_", r"exec\s*\(",
                    r"execute\s*\(", r"select.*from.*where", r"having", r"group_concat"
                ],
                'severity': 'CRITICAL'
            },
            {
                'name': 'XSS_ATTACK',
                'patterns': [
                    r"<script[^>]*>.*?</script>", r"javascript:", r"on\w+\s*=",
                    r"<iframe", r"<object", r"<embed", r"<img.*onerror",
                    r"<svg.*on\w+", r"alert\s*\(", r"confirm\s*\(", r"prompt\s*\(",
                    r"<body.*on\w+", r"<input.*on\w+", r"<img.*src=.*javascript"
                ],
                'severity': 'HIGH'
            },
            {
                'name': 'LOCAL_FILE_INCLUSION',
                'patterns': [
                    r"\.{2}/", r"\.{2}\\", r"/etc/passwd", r"/etc/shadow",
                    r"/proc/", r"file://", r"\\\\.*\\.*", r"c:\\\\windows",
                    r"c:\\\\winnt", r"%2e%2e/", r"..;/", r"php://"
                ],
                'severity': 'HIGH'
            },
            {
                'name': 'COMMAND_INJECTION',
                'patterns': [
                    r";", r"\|", r"&", r"`", r"\$\(", r"exec\s*\(",
                    r"system\s*\(", r"passthru\s*\(", r"shell_exec\s*\(",
                    r"whoami", r"ifconfig", r"ipconfig", r"cat\s+"
                ],
                'severity': 'CRITICAL'
            },
            {
                'name': 'DIRECTORY_TRAVERSAL',
                'patterns': [
                    r"\.\./", r"\..\\", r"%2e%2e/", r"%2e%2e\\",
                    r"..%2f", r"..%5c", r"..%3f", r"..%3b"
                ],
                'severity': 'MEDIUM'
            }
        ]
    
    def detect_threats(self, request: Dict) -> Dict:
        """Detect threats in request"""
        request_str = self._flatten_request(request)
        request_str_lower = request_str.lower()
        
        for rule in self.rules:
            for pattern in rule['patterns']:
                if re.search(pattern, request_str_lower, re.IGNORECASE):
                    return {
                        'threat_detected': True,
                        'threat_type': rule['name'],
                        'severity': rule['severity'],
                        'pattern_matched': pattern
                    }
        
        return {'threat_detected': False}
    
    def _flatten_request(self, request: Dict) -> str:
        """Flatten request object to searchable string"""
        flat = ""
        for key, value in request.items():
            if isinstance(value, str):
                flat += value + " "
            elif isinstance(value, dict):
                flat += str(value) + " "
            elif isinstance(value, list):
                flat += " ".join(str(v) for v in value) + " "
        return flat
