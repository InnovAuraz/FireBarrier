import pytest
import sys
import os
import numpy as np

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from models.anomaly_detector import ml_detector, MLAnomalyDetector
from models.lstm_detector import lstm_detector, LSTMThreatDetector
from models.advanced_threats import advanced_detector, AdvancedThreatDetector


class TestMLAnomalyDetector:
    def test_initialization(self):
        detector = MLAnomalyDetector()
        assert detector.is_trained == False
        assert detector.model is None
    
    def test_feature_extraction(self):
        detector = MLAnomalyDetector()
        packet = {
            'size': 1500,
            'src_port': 5000,
            'dst_port': 443,
            'type': 'TCP',
            'src_ip': '192.168.1.100'
        }
        features = detector.extract_features(packet)
        assert len(features) == 5
        assert features[0] == 1500  # size
        assert features[1] == 5000  # src_port
        assert features[2] == 443   # dst_port
        assert features[3] == 1     # TCP type
    
    def test_training_with_sufficient_data(self):
        detector = MLAnomalyDetector()
        packets = []
        for i in range(50):
            packets.append({
                'size': 100 + i,
                'src_port': 1000 + i,
                'dst_port': 80,
                'type': 'TCP',
                'src_ip': f'192.168.1.{i}'
            })
        
        result = detector.train(packets)
        assert result == True
        assert detector.is_trained == True
    
    def test_training_insufficient_data(self):
        detector = MLAnomalyDetector()
        packets = [{'size': 100, 'src_port': 80, 'dst_port': 443, 'type': 'TCP', 'src_ip': '192.168.1.1'}]
        result = detector.train(packets)
        assert result == False
        assert detector.is_trained == False


class TestLSTMDetector:
    def test_initialization(self):
        detector = LSTMThreatDetector()
        assert detector.is_trained == False
        assert detector.sequence_length == 10
        assert detector.feature_dim == 8
    
    def test_feature_extraction(self):
        detector = LSTMThreatDetector()
        packet = {
            'size': 1500,
            'src_port': 5000,
            'dst_port': 443,
            'protocol': 6,
            'type': 'TCP',
            'payload': b'test' * 10,
            'timestamp': 1234567890.0
        }
        features = detector.extract_features(packet)
        assert len(features) == 8
        assert features[0] == 1500.0  # size
        assert features[1] == 5000.0  # src_port
        assert features[2] == 443.0   # dst_port
        assert features[4] == 1.0     # is_tcp
        assert features[5] == 0.0     # is_udp
    
    def test_sequence_collection(self):
        detector = LSTMThreatDetector()
        for i in range(5):
            packet = {
                'size': 100 + i,
                'src_port': 1000,
                'dst_port': 80,
                'protocol': 6,
                'type': 'TCP',
                'payload': b'test',
                'timestamp': 1234567890.0 + i
            }
            detector.add_packet_sequence(packet, is_threat=False)
        
        assert len(detector.packet_sequences) == 5
    
    def test_get_stats(self):
        detector = LSTMThreatDetector()
        stats = detector.get_stats()
        assert 'is_trained' in stats
        assert 'sequences_collected' in stats
        assert 'sequences_needed' in stats
        assert 'sequence_length' in stats


class TestAdvancedThreatDetector:
    def test_initialization(self):
        detector = AdvancedThreatDetector()
        assert detector.ddos_threshold == 100
        assert detector.port_scan_threshold == 10
        assert len(detector.known_malware_ports) > 0
    
    def test_malicious_port_detection(self):
        detector = AdvancedThreatDetector()
        result = detector.detect_malicious_port(4444)  # Metasploit
        assert result['detected'] == True
        assert result['severity'] == 'CRITICAL'
        assert 'category' in result
    
    def test_safe_port(self):
        detector = AdvancedThreatDetector()
        result = detector.detect_malicious_port(443)  # HTTPS
        assert result['detected'] == False
    
    def test_sql_injection_detection(self):
        detector = AdvancedThreatDetector()
        payload = b"SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin"
        result = detector.detect_payload_attack(payload)
        assert result['detected'] == True
        assert result['type'] == 'SQL Injection'
        assert result['category'] == 'sql_injection'
    
    def test_xss_detection(self):
        detector = AdvancedThreatDetector()
        payload = b"<script>alert('XSS')</script>"
        result = detector.detect_payload_attack(payload)
        assert result['detected'] == True
        assert result['type'] == 'XSS Attack'
    
    def test_directory_traversal_detection(self):
        detector = AdvancedThreatDetector()
        payload = b"../../../../etc/passwd"
        result = detector.detect_payload_attack(payload)
        assert result['detected'] == True
        assert result['type'] == 'Directory Traversal'
    
    def test_command_injection_detection(self):
        detector = AdvancedThreatDetector()
        payload = b"input.txt; rm -rf /"
        result = detector.detect_payload_attack(payload)
        assert result['detected'] == False  # Need shell command keywords
        
        payload_win = b"cmd.exe /c dir"
        result = detector.detect_payload_attack(payload_win)
        assert result['detected'] == True
        assert result['type'] == 'Command Injection'
    
    def test_safe_payload(self):
        detector = AdvancedThreatDetector()
        payload = b"Hello World"
        result = detector.detect_payload_attack(payload)
        assert result['detected'] == False
    
    def test_analyze_packet_no_threat(self):
        detector = AdvancedThreatDetector()
        packet = {
            'src_ip': '192.168.1.100',
            'dst_port': 443,
            'payload': b'GET /index.html HTTP/1.1',
            'timestamp': 1234567890.0
        }
        result = detector.analyze_packet(packet)
        assert result['is_threat'] == False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])