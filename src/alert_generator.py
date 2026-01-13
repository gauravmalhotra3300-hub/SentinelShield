import time
import threading
from datetime import datetime
from collections import deque

class AlertGenerator:
    """Generates security alerts based on detected threats."""
    
    def __init__(self, max_alerts=1000):
        self.alerts = deque(maxlen=max_alerts)
        self.alert_count = 0
        self.severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        self.lock = threading.Lock()
        
    def generate_alert(self, threat_type, source_ip, request_data, severity='medium'):
        """Generate a security alert."""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat_type,
            'source_ip': source_ip,
            'request_data': request_data,
            'severity': severity,
            'alert_id': self.alert_count + 1
        }
        
        with self.lock:
            self.alerts.append(alert)
            self.alert_count += 1
            if severity in self.severity_counts:
                self.severity_counts[severity] += 1
        
        return alert
    
    def get_recent_alerts(self, limit=10):
        """Get recent alerts."""
        with self.lock:
            return list(self.alerts)[-limit:]
    
    def get_alerts_by_severity(self, severity):
        """Get alerts by severity level."""
        with self.lock:
            return [a for a in self.alerts if a['severity'] == severity]
    
    def get_alert_summary(self):
        """Get summary of all alerts."""
        with self.lock:
            return {
                'total_alerts': self.alert_count,
                'severity_distribution': dict(self.severity_counts),
                'recent_alerts': list(self.alerts)[-5:] if self.alerts else []
            }
    
    def get_alerts_by_source(self, source_ip):
        """Get all alerts from a specific source IP."""
        with self.lock:
            return [a for a in self.alerts if a['source_ip'] == source_ip]
    
    def clear_old_alerts(self, hours=24):
        """Clear alerts older than specified hours."""
        cutoff_time = datetime.now().timestamp() - (hours * 3600)
        with self.lock:
            self.alerts = deque(
                (a for a in self.alerts 
                 if datetime.fromisoformat(a['timestamp']).timestamp() > cutoff_time),
                maxlen=self.alerts.maxlen
            )
    
    def reset_alerts(self):
        """Reset all alerts."""
        with self.lock:
            self.alerts.clear()
            self.alert_count = 0
            for key in self.severity_counts:
                self.severity_counts[key] = 0
