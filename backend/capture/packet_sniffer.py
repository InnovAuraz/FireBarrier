from scapy.all import sniff, IP, TCP, UDP, conf
from models.advanced_threats import advanced_detector
import threading
import time
from models.anomaly_detector import ml_detector
from security.ip_blocker import ip_blocker  # NEW

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
        self.is_running = False
        self.training_done = False
        self.auto_block_enabled = True  # NEW: Enable auto-blocking
        self.threat_threshold = 3  # NEW: Block IP after 3 threats
        self.ip_threat_count = {}  # NEW: Track threats per IP
        
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
        
        # Get port info
        if packet.haslayer(TCP):
            packet_info['src_port'] = packet[TCP].sport
            packet_info['dst_port'] = packet[TCP].dport
            packet_info['type'] = 'TCP'
        elif packet.haslayer(UDP):
            packet_info['src_port'] = packet[UDP].sport
            packet_info['dst_port'] = packet[UDP].dport
            packet_info['type'] = 'UDP'
        else:
            packet_info['type'] = 'OTHER'
        
        # Rule-based detection
        rule_threat = simple_threat_check(packet_info)
        
        # ML-based detection (only after training)
        ml_threat = False
        if self.training_done and ml_detector.is_trained:
            ml_threat = ml_detector.is_anomaly(packet_info)
            if ml_threat:
                self.ml_threats += 1
        
        # Mark as threat if either method flags it
        packet_info['threat'] = bool(rule_threat or ml_threat)
        packet_info['detection_method'] = 'Rule-based' if rule_threat else ('ML' if ml_threat else 'Safe')
        packet_info['blocked'] = False  # NEW: Track if IP was blocked
        
        if packet_info['threat']:
            self.total_threats += 1
            src_ip = packet_info.get('src_ip')
            
            # Track threats per IP
            if src_ip and src_ip not in ['127.0.0.1', 'localhost']:  # Don't block localhost
                self.ip_threat_count[src_ip] = self.ip_threat_count.get(src_ip, 0) + 1
                
                # Auto-block if threshold reached
                if self.auto_block_enabled and self.ip_threat_count[src_ip] >= self.threat_threshold:
                    if not ip_blocker.is_blocked(src_ip):
                        # Only block external IPs (not local network)
                        if not src_ip.startswith('192.168.') and not src_ip.startswith('10.'):
                            if ip_blocker.block_ip(src_ip):
                                packet_info['blocked'] = True
                                print(f"🚫 AUTO-BLOCKED: {src_ip} (reached {self.ip_threat_count[src_ip]} threats)")
            
            print(f"🚨 THREAT #{self.total_threats} [{packet_info['detection_method']}]: {src_ip} -> {packet_info.get('dst_ip')} Port: {packet_info.get('dst_port')}")
            
            self.threat_list.append(packet_info)
            
            if len(self.threat_list) > 10:
                self.threat_list.pop(0)
        
        self.packet_list.append(packet_info)
        
        if len(self.packet_list) > 100:
            self.packet_list.pop(0)
        
        # Auto-train ML model after collecting 50 packets
        if self.total_packets == 50 and not self.training_done:
            print("🧠 Auto-training ML model...")
            if ml_detector.train(self.packet_list):
                self.training_done = True
        
        if self.total_packets % 10 == 0:
            blocked_count = len(ip_blocker.get_blocked_ips())
            print(f"📦 Captured {self.total_packets} packets | ML Threats: {self.ml_threats} | Blocked IPs: {blocked_count}")
    
    def start_capture(self):
        """Start capturing packets in background"""
        self.is_running = True
        
        def capture():
            print("🔍 Starting packet capture (Layer 3)...")
            try:
                sniff(filter="ip", prn=self.packet_callback, store=False)
            except Exception as e:
                print(f"❌ Capture error: {e}")
        
        thread = threading.Thread(target=capture, daemon=True)
        thread.start()
        print("✅ Packet capture started!")
    
    def get_stats(self):
        """Return current statistics"""
        return {
            'total_packets': self.total_packets,
            'threats_detected': self.total_threats,
            'ml_threats': self.ml_threats,
            'ml_trained': self.training_done,
            'recent_packets': self.packet_list[-10:] if self.packet_list else []
        }

packet_capture = PacketCapture()
