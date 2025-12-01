from scapy.all import sniff, IP, TCP, UDP, Raw, conf
import threading
import time
from models.anomaly_detector import ml_detector
from security.ip_blocker import ip_blocker
from models.advanced_threats import advanced_detector
from models.lstm_detector import lstm_detector
from models.cnn_detector import CNNDetector  # NEW: Layer 5
from config import config
from utils.logger import logger, log_threat, log_block
from capture.detection_queue import DetectionQueue

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
        self.lstm_threats = 0
        self.cnn_threats = 0  # NEW: Layer 5
        self.is_running = False
        self.training_done = False
        self.auto_block_enabled = True
        self.threat_threshold = config.THREAT_THRESHOLD
        self.ip_threat_count = {}
        
        # Initialize CNN detector (Layer 5)
        self.cnn_detector = CNNDetector()
        logger.info("CNN Detector initialized")
        
        # Initialize async detection queue
        self.detection_queue = DetectionQueue(ml_detector, lstm_detector, advanced_detector)
        
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
    
    def extract_packet_features(self, packet):
        """Fast feature extraction from packet (sync operation)"""
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
        
        return packet_info
        
    def packet_callback(self, packet):
        """Process each captured packet"""
        self.total_packets += 1
        
        # Fast feature extraction
        packet_info = self.extract_packet_features(packet)
        
        # Fast rule-based detection (keep synchronous)
        rule_threat = simple_threat_check(packet_info)
        
        # Layer 5: CNN Detection (synchronous for real-time feedback)
        cnn_threat = False
        cnn_probability = 0.0
        
        if self.cnn_detector.is_trained:
            cnn_threat, cnn_probability = self.cnn_detector.predict(packet_info)
            if cnn_threat:
                self.cnn_threats += 1
                logger.info(f"CNN detected anomaly: {cnn_probability:.3f}")
        else:
            # Collect training samples using rule-based label initially
            # Will be improved with combined detection after async results available
            self.cnn_detector.collect_sample(packet_info, rule_threat)
            
            # Check if ready to train
            if self.cnn_detector.should_train():
                logger.info("CNN training threshold reached, starting training...")
                self.cnn_detector.train()
        
        # Enqueue for async ML/LSTM/Advanced detection (offload heavy computation)
        self.detection_queue.enqueue(packet_info.copy())
        
        # Store packet immediately (don't wait for ML/LSTM results)
        self.packet_list.append(packet_info)
        if len(self.packet_list) > 100:
            self.packet_list.pop(0)
        
        # Mark as threat if detected by rule-based OR CNN
        # ML/LSTM results will be processed by detection_queue worker
        is_threat = rule_threat or cnn_threat
        
        if is_threat:
            packet_info['threat'] = True
            
            # Build detection methods list
            detection_methods = []
            if rule_threat:
                detection_methods.append('Rule')
            if cnn_threat:
                detection_methods.append('CNN')
            
            packet_info['detection_method'] = ', '.join(detection_methods)
            packet_info['severity'] = 'HIGH' if cnn_threat else 'MEDIUM'
            packet_info['threat_types'] = ['CNN Anomaly'] if cnn_threat else ['Suspicious Pattern']
            packet_info['blocked'] = False
            
            self.total_threats += 1
            self.threat_list.append(packet_info)
            if len(self.threat_list) > 10:
                self.threat_list.pop(0)
            
            # Log threat
            log_threat(packet_info, 'Rule', 'MEDIUM')
            
            # Track threats per IP and handle auto-blocking
            src_ip = packet_info.get('src_ip')
            if src_ip and src_ip not in ['127.0.0.1', 'localhost']:
                self.ip_threat_count[src_ip] = self.ip_threat_count.get(src_ip, 0) + 1
                
                # Auto-block based on threshold
                if self.ip_threat_count[src_ip] >= self.threat_threshold:
                    if self.auto_block_enabled and not ip_blocker.is_blocked(src_ip):
                        if not src_ip.startswith('192.168.') and not src_ip.startswith('10.'):
                            if ip_blocker.block_ip(src_ip):
                                packet_info['blocked'] = True
                                threat_count = self.ip_threat_count[src_ip]
                                log_block(src_ip, f"Exceeded threshold ({threat_count}/{config.THREAT_THRESHOLD})")
        
        # Auto-train ML model
        if self.total_packets == config.ISOLATION_TRAIN_AT and not self.training_done:
            logger.info("Auto-training ML model...")
            if ml_detector.train(self.packet_list):
                self.training_done = True
        
        # NEW: Auto-train LSTM model
        if self.total_packets % 100 == 0:
            lstm_stats = lstm_detector.get_stats()
            if not lstm_detector.is_trained and lstm_stats['sequences_needed'] == 0:
                logger.info("Auto-training LSTM model...")
                lstm_detector.train()
        
        # Periodic cleanup
        if self.total_packets % 100 == 0:
            advanced_detector.clear_old_data()
        
        if self.total_packets % 10 == 0:
            blocked_count = len(ip_blocker.get_blocked_ips())
            logger.info(f"📦 Packets: {self.total_packets} | Threats: {self.total_threats} | ML: {self.ml_threats} | LSTM: {self.lstm_threats} | CNN: {self.cnn_threats} | Blocked: {blocked_count}")
    
    def start_capture(self):
        """Start capturing packets in background"""
        self.is_running = True
        
        # Start detection queue worker
        self.detection_queue.start()
        
        def capture():
            logger.info("🔍 Starting packet capture with async detection...")
            try:
                sniff(filter="ip", prn=self.packet_callback, store=False)
            except Exception as e:
                logger.error(f"❌ Capture error: {e}")
        
        thread = threading.Thread(target=capture, daemon=True)
        thread.start()
        logger.success("✅ Packet capture started!")
    
    def stop_capture(self):
        """Stop packet capture and detection queue"""
        self.is_running = False
        self.detection_queue.stop()
        logger.info("Packet capture stopped")
    
    def get_stats(self):
        """Return current statistics"""
        lstm_stats = lstm_detector.get_stats()
        cnn_stats = self.cnn_detector.get_stats()
        
        return {
            'total_packets': self.total_packets,
            'threats_detected': self.total_threats,
            'ml_threats': self.ml_threats,
            'lstm_threats': self.lstm_threats,
            'cnn_threats': self.cnn_threats,
            'lstm_stats': lstm_stats,
            'cnn_stats': cnn_stats,
            'ml_trained': self.training_done,
            'threat_stats': self.threat_stats,
            'recent_packets': self.packet_list[-10:] if self.packet_list else [],
            'detection_queue_size': self.detection_queue.get_queue_size()
        }


packet_capture = PacketCapture()
