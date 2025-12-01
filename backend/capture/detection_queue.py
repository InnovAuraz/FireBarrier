import asyncio
from queue import Queue
from threading import Thread
from utils.logger import logger

class DetectionQueue:
    def __init__(self, ml_detector, lstm_detector, advanced_detector):
        self.queue = Queue(maxsize=1000)
        self.ml_detector = ml_detector
        self.lstm_detector = lstm_detector
        self.advanced_detector = advanced_detector
        self.running = False
        self.worker_thread = None
    
    def start(self):
        """Start the background worker thread"""
        self.running = True
        self.worker_thread = Thread(target=self._worker, daemon=True)
        self.worker_thread.start()
        logger.info("Detection queue worker started")
    
    def stop(self):
        """Stop the worker thread gracefully"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
        logger.info("Detection queue worker stopped")
    
    def enqueue(self, packet_info):
        """Add packet to detection queue"""
        if self.queue.full():
            logger.warning("Detection queue full, dropping packet")
            return False
        self.queue.put(packet_info)
        return True
    
    def _worker(self):
        """Background worker that processes queued packets"""
        while self.running:
            try:
                packet_info = self.queue.get(timeout=1)
                self._process_packet(packet_info)
                self.queue.task_done()
            except Exception as e:
                if self.running:  # Only log if not shutting down
                    logger.debug(f"Worker exception: {e}")
                continue
    
    def _process_packet(self, packet_info):
        """Run all detection methods on a single packet"""
        try:
            # ML detection (Isolation Forest)
            ml_threat = False
            if self.ml_detector.is_trained:
                ml_threat = self.ml_detector.is_anomaly(packet_info)
            
            # Advanced pattern detection
            advanced_result = self.advanced_detector.analyze_packet(packet_info)
            advanced_threat = advanced_result.get('is_threat', False)
            threats = advanced_result.get('threats', [])
            severity = advanced_result.get('severity', 'LOW')
            
            # LSTM sequential detection
            lstm_threat = False
            if self.lstm_detector.is_trained:
                lstm_threat = self.lstm_detector.predict_threat(packet_info)
            
            # Aggregate results
            is_threat = ml_threat or advanced_threat or lstm_threat
            
            detection_methods = []
            if ml_threat:
                detection_methods.append('ML')
            if advanced_threat:
                detection_methods.append('Advanced')
            if lstm_threat:
                detection_methods.append('LSTM')
            
            # Store detection results in packet_info
            packet_info['ml_threat'] = ml_threat
            packet_info['advanced_threat'] = advanced_threat
            packet_info['lstm_threat'] = lstm_threat
            packet_info['is_threat'] = is_threat
            packet_info['detection_methods'] = detection_methods
            packet_info['severity'] = severity
            packet_info['threat_categories'] = [t.get('category', 'unknown') for t in threats]
            
            return {
                'is_threat': is_threat,
                'ml_threat': ml_threat,
                'advanced_threat': advanced_threat,
                'lstm_threat': lstm_threat,
                'detection_methods': detection_methods,
                'severity': severity,
                'threats': threats
            }
            
        except Exception as e:
            logger.error(f"Error processing packet in detection queue: {e}")
            return {
                'is_threat': False,
                'ml_threat': False,
                'advanced_threat': False,
                'lstm_threat': False,
                'detection_methods': [],
                'severity': 'LOW',
                'threats': []
            }
    
    def get_queue_size(self):
        """Get current queue size"""
        return self.queue.qsize()
    
    def is_running(self):
        """Check if worker is running"""
        return self.running
