from collections import defaultdict
import time
from typing import Dict, List

class AdvancedThreatDetector:
    def __init__(self):
        # DDoS Detection
        self.connection_tracker = defaultdict(list)
        self.ddos_threshold = 100
        self.ddos_window = 1
        
        # Port Scan Detection
        self.port_scanner = defaultdict(set)
        self.port_scan_threshold = 10
        self.port_scan_window = 5
        self.port_scan_timestamps = defaultdict(float)
        
        # Known malicious ports
        self.known_malware_ports = {
            1337: 'DOOM Trojan',
            31337: 'Back Orifice',
            12345: 'NetBus',
            6667: 'IRC Botnet',
            6666: 'IRC Botnet Alt',
            4444: 'Metasploit',
            5555: 'Android Debug',
            8080: 'Proxy/Backdoor'
        }
    
    def detect_ddos(self, src_ip: str, timestamp: float) -> Dict:
        """Detect DDoS attack"""
        self.connection_tracker[src_ip].append(timestamp)
        cutoff = timestamp - self.ddos_window
        self.connection_tracker[src_ip] = [
            ts for ts in self.connection_tracker[src_ip] if ts > cutoff
        ]
        
        packet_count = len(self.connection_tracker[src_ip])
        
        if packet_count > self.ddos_threshold:
            return {
                'detected': True,
                'type': 'DDoS Attack',
                'severity': 'CRITICAL',
                'details': f'{packet_count} packets/sec from {src_ip}',
                'category': 'ddos'
            }
        return {'detected': False}
    
    def detect_port_scan(self, src_ip: str, dst_port: int, timestamp: float) -> Dict:
        """Detect port scanning"""
        if dst_port is None:
            return {'detected': False}
        
        self.port_scanner[src_ip].add(dst_port)
        
        if src_ip not in self.port_scan_timestamps:
            self.port_scan_timestamps[src_ip] = timestamp
        
        time_elapsed = timestamp - self.port_scan_timestamps[src_ip]
        
        if time_elapsed <= self.port_scan_window:
            unique_ports = len(self.port_scanner[src_ip])
            
            if unique_ports >= self.port_scan_threshold:
                ports_list = sorted(list(self.port_scanner[src_ip]))[:20]
                return {
                    'detected': True,
                    'type': 'Port Scan',
                    'severity': 'HIGH',
                    'details': f'{unique_ports} ports scanned: {ports_list}',
                    'category': 'port_scan'
                }
        else:
            self.port_scanner[src_ip] = {dst_port}
            self.port_scan_timestamps[src_ip] = timestamp
        
        return {'detected': False}
    
    def detect_malicious_port(self, dst_port: int) -> Dict:
        """Check for known malware ports"""
        if dst_port in self.known_malware_ports:
            return {
                'detected': True,
                'type': 'Malware Communication',
                'severity': 'CRITICAL',
                'details': f'Port {dst_port}: {self.known_malware_ports[dst_port]}',
                'category': 'malware'
            }
        return {'detected': False}
    
    def detect_payload_attack(self, payload: bytes) -> Dict:
        """Analyze packet payload"""
        if not payload:
            return {'detected': False}
        
        payload_lower = payload.lower()
        
        # SQL Injection
        if any(p in payload_lower for p in [b'select', b'union', b'drop table']):
            return {
                'detected': True,
                'type': 'SQL Injection',
                'severity': 'HIGH',
                'details': 'SQL keywords in payload',
                'category': 'sql_injection'
            }
        
        # XSS
        if any(p in payload_lower for p in [b'<script', b'javascript:', b'onerror=']):
            return {
                'detected': True,
                'type': 'XSS Attack',
                'severity': 'MEDIUM',
                'details': 'Script injection detected',
                'category': 'xss'
            }
        
        # Directory Traversal
        if b'../' in payload or b'..\\' in payload:
            return {
                'detected': True,
                'type': 'Directory Traversal',
                'severity': 'HIGH',
                'details': 'Path traversal attempt',
                'category': 'directory_traversal'
            }
        
        # Command Injection
        if any(p in payload_lower for p in [b'cmd.exe', b'/bin/bash', b'powershell']):
            return {
                'detected': True,
                'type': 'Command Injection',
                'severity': 'CRITICAL',
                'details': 'Shell command in payload',
                'category': 'command_injection'
            }
        
        return {'detected': False}
    
    def analyze_packet(self, packet_info: Dict) -> Dict:
        """Comprehensive threat analysis"""
        threats = []
        max_severity = 'LOW'
        
        timestamp = packet_info.get('timestamp', time.time())
        src_ip = packet_info.get('src_ip')
        dst_port = packet_info.get('dst_port')
        payload = packet_info.get('payload', b'')
        
        # Check DDoS
        if src_ip:
            ddos_result = self.detect_ddos(src_ip, timestamp)
            if ddos_result['detected']:
                threats.append(ddos_result)
                max_severity = 'CRITICAL'
        
        # Check Port Scan
        if src_ip and dst_port:
            scan_result = self.detect_port_scan(src_ip, dst_port, timestamp)
            if scan_result['detected']:
                threats.append(scan_result)
                if max_severity != 'CRITICAL':
                    max_severity = 'HIGH'
        
        # Check Malicious Port
        if dst_port:
            malware_result = self.detect_malicious_port(dst_port)
            if malware_result['detected']:
                threats.append(malware_result)
                max_severity = 'CRITICAL'
        
        # Check Payload
        if payload:
            payload_result = self.detect_payload_attack(payload)
            if payload_result['detected']:
                threats.append(payload_result)
                if max_severity == 'LOW':
                    max_severity = payload_result['severity']
        
        if threats:
            return {
                'is_threat': True,
                'threats': threats,
                'severity': max_severity,
                'threat_count': len(threats)
            }
        
        return {'is_threat': False}
    
    def clear_old_data(self):
        """Clear old tracking data"""
        current_time = time.time()
        
        # Clear old DDoS data
        for ip in list(self.connection_tracker.keys()):
            cutoff = current_time - self.ddos_window * 2
            self.connection_tracker[ip] = [
                ts for ts in self.connection_tracker[ip] if ts > cutoff
            ]
            if not self.connection_tracker[ip]:
                del self.connection_tracker[ip]
        
        # Clear old port scan data
        for ip in list(self.port_scan_timestamps.keys()):
            if current_time - self.port_scan_timestamps[ip] > self.port_scan_window * 2:
                del self.port_scan_timestamps[ip]
                if ip in self.port_scanner:
                    del self.port_scanner[ip]

# Global instance
advanced_detector = AdvancedThreatDetector()
