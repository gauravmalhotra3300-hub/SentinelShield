import time
import threading
from collections import defaultdict

class TrafficAnalyzer:
    """Analyzes network traffic patterns and statistics."""
    
    def __init__(self):
        self.traffic_stats = defaultdict(lambda: {'requests': 0, 'bytes': 0, 'last_seen': 0})
        self.protocol_stats = defaultdict(int)
        self.method_stats = defaultdict(int)
        self.status_stats = defaultdict(int)
        self.lock = threading.Lock()
        
    def record_request(self, source_ip, request_size, method, status_code, protocol='HTTP'):
        """Record traffic from a source IP."""
        with self.lock:
            self.traffic_stats[source_ip]['requests'] += 1
            self.traffic_stats[source_ip]['bytes'] += request_size
            self.traffic_stats[source_ip]['last_seen'] = time.time()
            self.protocol_stats[protocol] += 1
            self.method_stats[method] += 1
            self.status_stats[status_code] += 1
    
    def get_traffic_summary(self):
        """Get summary of traffic statistics."""
        with self.lock:
            total_requests = sum(stats['requests'] for stats in self.traffic_stats.values())
            total_bytes = sum(stats['bytes'] for stats in self.traffic_stats.values())
            
            return {
                'total_requests': total_requests,
                'total_bytes': total_bytes,
                'unique_sources': len(self.traffic_stats),
                'protocols': dict(self.protocol_stats),
                'methods': dict(self.method_stats),
                'status_codes': dict(self.status_stats)
            }
    
    def get_top_sources(self, limit=10):
        """Get top source IPs by request count."""
        with self.lock:
            sorted_sources = sorted(self.traffic_stats.items(), 
                                  key=lambda x: x[1]['requests'], 
                                  reverse=True)
            return sorted_sources[:limit]
    
    def is_high_volume_source(self, source_ip, threshold=100):
        """Check if source IP has high request volume."""
        with self.lock:
            return self.traffic_stats[source_ip]['requests'] > threshold
    
    def reset_stats(self):
        """Reset all statistics."""
        with self.lock:
            self.traffic_stats.clear()
            self.protocol_stats.clear()
            self.method_stats.clear()
            self.status_stats.clear()
