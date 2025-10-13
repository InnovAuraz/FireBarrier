from scapy.all import sniff, IP, TCP, UDP, Raw, conf
import threading
import time
from models.anomaly_detector import ml_detector
from security.ip_blocker import ip_blocker
from models.advanced_threats import advanced_detector
from models.lstm_detector import lstm_detector  # NEW

# Use Layer 3 socket for Windows
conf.L3socket = conf.L3socket


def simple_threat_check(packet_info):
    """Check if packet looks suspicious (Rule-based)"""
    suspicious_ports = {4444, 1337, 6667, 23, 2323}
    
    if packet_info.get('src_port') in suspicious_ports or packet_info.get('dst_port') in suspicious_ports:
        return True
    
    if packet_info.get('size', 100) > 1200 or packet_info.get('size', 100) < 30:
        return True
    
    return False


class PacketCapture:
    def __init__(self):
        self.total_packets = 0
        self.packet_list = []
        self.threat_list = []
        self.total_threats = 0
        self.ml_threats = 0
        self.lstm_threats = 0  # NEW
        self.is_running = False
        self.training_done = False
        self.auto_block_enabled = True
        self.threat_threshold = 10
        self.ip_threat_count = {}
        
        # NEW: Threat statistics by category
        self.threat_stats = {
            'ddos': 0,
            'port_scan': 0,
            'malware': 0,
            'sql_injection': 0,
            'xss': 0,
            'command_injection': 0,
            'directory_traversal': 0
        }
        
    def packet_callback(self, packet):
        """Process each captured packet"""
        self.total_packets += 1
        
        # Extract basic info
        packet_info = {
            'id': self.total_packets,
            'timestamp': time.time(),
            'size': len(packet)
        }
        
        # Get IP layer info
        if packet.haslayer(IP):
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['protocol'] = packet[IP].proto
        
        # Get port info and payload
        if packet.haslayer(TCP):
            packet_info['src_port'] = packet[TCP].sport
            packet_info['dst_port'] = packet[TCP].dport
            packet_info['type'] = 'TCP'
            if packet.haslayer(Raw):
                packet_info['payload'] = bytes(packet[Raw].load)
        elif packet.haslayer(UDP):
            packet_info['src_port'] = packet[UDP].sport
            packet_info['dst_port'] = packet[UDP].dport
            packet_info['type'] = 'UDP'
            if packet.haslayer(Raw):
                packet_info['payload'] = bytes(packet[Raw].load)
        else:
            packet_info['type'] = 'OTHER'
        
        # Rule-based detection
        rule_threat = simple_threat_check(packet_info)
        
        # ML-based detection
        ml_threat = False
        if self.training_done and ml_detector.is_trained:
            ml_threat = ml_detector.is_anomaly(packet_info)
            if ml_threat:
                self.ml_threats += 1
        
        # Advanced threat detection
        advanced_result = advanced_detector.analyze_packet(packet_info)
        advanced_threat = advanced_result.get('is_threat', False)
        
        # NEW: LSTM Sequential Detection
        lstm_threat = False
        if lstm_detector.is_trained:
            lstm_threat = lstm_detector.predict_threat(packet_info)
            if lstm_threat:
                self.lstm_threats += 1
        
        # Combine all detection methods
        is_threat = rule_threat or ml_threat or advanced_threat or lstm_threat
        
        # Determine detection method and severity
        detection_methods = []
        threat_details = []
        severity = 'LOW'
        
        if rule_threat:
            detection_methods.append('Rule')
        if ml_threat:
            detection_methods.append('ML')
        if advanced_threat:
            detection_methods.append('Advanced')
            severity = advanced_result.get('severity', 'MEDIUM')
            for threat in advanced_result.get('threats', []):
                threat_details.append(threat['type'])
                category = threat.get('category', 'unknown')
                if category in self.threat_stats:
                    self.threat_stats[category] += 1
        if lstm_threat:
            detection_methods.append('LSTM')
            threat_details.append('Sequential Pattern')
            if severity == 'LOW':
                severity = 'HIGH'
        
        # NEW: Feed packet to LSTM for learning
        lstm_detector.add_packet_sequence(packet_info, is_threat=is_threat)
        
        packet_info['threat'] = bool(is_threat)
        packet_info['detection_method'] = '+'.join(detection_methods) if detection_methods else 'Safe'
        packet_info['threat_types'] = threat_details if threat_details else []
        packet_info['severity'] = severity
        packet_info['blocked'] = False
        
        if packet_info['threat']:
            self.total_threats += 1
            src_ip = packet_info.get('src_ip')
            
            # Track threats per IP
            if src_ip and src_ip not in ['127.0.0.1', 'localhost']:
                self.ip_threat_count[src_ip] = self.ip_threat_count.get(src_ip, 0) + 1
                
                # Auto-block based on severity or threshold
                should_block = False
                if severity == 'CRITICAL':
                    should_block = True
                elif self.ip_threat_count[src_ip] >= self.threat_threshold:
                    should_block = True
                
                if self.auto_block_enabled and should_block:
                    if not ip_blocker.is_blocked(src_ip):
                        if not src_ip.startswith('192.168.') and not src_ip.startswith('10.'):
                            if ip_blocker.block_ip(src_ip):
                                packet_info['blocked'] = True
                                print(f"🚫 AUTO-BLOCKED [{severity}]: {src_ip} - {', '.join(threat_details)}")
            
            threat_info = f" ({', '.join(threat_details)})" if threat_details else ""
            print(f"🚨 THREAT #{self.total_threats} [{packet_info['detection_method']}] {severity}: {src_ip} -> {packet_info.get('dst_ip')} Port: {packet_info.get('dst_port')}{threat_info}")
            
            self.threat_list.append(packet_info)
            if len(self.threat_list) > 10:
                self.threat_list.pop(0)
        
        self.packet_list.append(packet_info)
        if len(self.packet_list) > 100:
            self.packet_list.pop(0)
        
        # Auto-train ML model
        if self.total_packets == 50 and not self.training_done:
            print("🧠 Auto-training ML model...")
            if ml_detector.train(self.packet_list):
                self.training_done = True
        
        # NEW: Auto-train LSTM model
        if self.total_packets % 100 == 0:
            lstm_stats = lstm_detector.get_stats()
            if not lstm_detector.is_trained and lstm_stats['sequences_needed'] == 0:
                print("🧠 Auto-training LSTM model...")
                lstm_detector.train()
        
        # Periodic cleanup
        if self.total_packets % 100 == 0:
            advanced_detector.clear_old_data()
        
        if self.total_packets % 10 == 0:
            blocked_count = len(ip_blocker.get_blocked_ips())
            print(f"📦 Packets: {self.total_packets} | Threats: {self.total_threats} | ML: {self.ml_threats} | LSTM: {self.lstm_threats} | Blocked: {blocked_count}")
    
    def start_capture(self):
        """Start capturing packets in background"""
        self.is_running = True
        
        def capture():
            print("🔍 Starting packet capture with LSTM detection...")
            try:
                sniff(filter="ip", prn=self.packet_callback, store=False)
            except Exception as e:
                print(f"❌ Capture error: {e}")
        
        thread = threading.Thread(target=capture, daemon=True)
        thread.start()
        print("✅ Packet capture started!")
    
    def get_stats(self):
        """Return current statistics"""
        lstm_stats = lstm_detector.get_stats()
        
        return {
            'total_packets': self.total_packets,
            'threats_detected': self.total_threats,
            'ml_threats': self.ml_threats,
            'lstm_threats': self.lstm_threats,  # NEW
            'lstm_stats': lstm_stats,  # NEW
            'ml_trained': self.training_done,
            'threat_stats': self.threat_stats,
            'recent_packets': self.packet_list[-10:] if self.packet_list else []
        }


packet_capture = PacketCapture()
