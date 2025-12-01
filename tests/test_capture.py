import pytest
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from capture.packet_sniffer import PacketCapture, simple_threat_check


class TestSimpleThreatCheck:
    def test_suspicious_port_detection(self):
        packet = {'src_port': 4444, 'dst_port': 80, 'size': 100}
        assert simple_threat_check(packet) == True
    
    def test_large_packet_detection(self):
        packet = {'src_port': 80, 'dst_port': 443, 'size': 1500}
        assert simple_threat_check(packet) == True
    
    def test_small_packet_detection(self):
        packet = {'src_port': 80, 'dst_port': 443, 'size': 20}
        assert simple_threat_check(packet) == True
    
    def test_normal_packet(self):
        packet = {'src_port': 80, 'dst_port': 443, 'size': 500}
        assert simple_threat_check(packet) == False


class TestPacketCapture:
    def test_initialization(self):
        capture = PacketCapture()
        assert capture.total_packets == 0
        assert capture.total_threats == 0
        assert capture.is_running == False
        assert capture.auto_block_enabled == True
    
    def test_get_stats_structure(self):
        capture = PacketCapture()
        stats = capture.get_stats()
        
        assert 'total_packets' in stats
        assert 'threats_detected' in stats
        assert 'ml_threats' in stats
        assert 'lstm_threats' in stats
        assert 'ml_trained' in stats
        assert 'lstm_stats' in stats
        assert 'threat_stats' in stats
    
    def test_threat_stats_categories(self):
        capture = PacketCapture()
        assert 'ddos' in capture.threat_stats
        assert 'port_scan' in capture.threat_stats
        assert 'malware' in capture.threat_stats
        assert 'sql_injection' in capture.threat_stats
        assert 'xss' in capture.threat_stats
        assert 'command_injection' in capture.threat_stats
        assert 'directory_traversal' in capture.threat_stats


if __name__ == '__main__':
    pytest.main([__file__, '-v'])