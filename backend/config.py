import os
from dotenv import load_dotenv
from typing import List

load_dotenv()

class Config:
    # Detection Thresholds
    THREAT_THRESHOLD: int = int(os.getenv("THREAT_THRESHOLD", "10"))
    LSTM_PREDICTION_THRESHOLD: float = float(os.getenv("LSTM_PREDICTION_THRESHOLD", "0.5"))
    CNN_PREDICTION_THRESHOLD: float = float(os.getenv("CNN_PREDICTION_THRESHOLD", "0.6"))
    ISOLATION_CONTAMINATION: float = float(os.getenv("ISOLATION_CONTAMINATION", "0.15"))
    DDOS_THRESHOLD: int = int(os.getenv("DDOS_THRESHOLD", "100"))
    DDOS_WINDOW: int = int(os.getenv("DDOS_WINDOW", "1"))
    PORT_SCAN_THRESHOLD: int = int(os.getenv("PORT_SCAN_THRESHOLD", "10"))
    PORT_SCAN_WINDOW: int = int(os.getenv("PORT_SCAN_WINDOW", "5"))
    
    # Training
    ISOLATION_TRAIN_AT: int = int(os.getenv("ISOLATION_TRAIN_AT", "50"))
    LSTM_MIN_SEQUENCES: int = int(os.getenv("LSTM_MIN_SEQUENCES", "100"))
    LSTM_SEQUENCE_LENGTH: int = int(os.getenv("LSTM_SEQUENCE_LENGTH", "10"))
    CNN_MIN_SAMPLES: int = int(os.getenv("CNN_MIN_SAMPLES", "200"))
    
    # API
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))
    CORS_ORIGINS: List[str] = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
    
    # Security
    API_AUTH_ENABLED: bool = os.getenv("API_AUTH_ENABLED", "false").lower() == "true"
    API_SECRET_KEY: str = os.getenv("API_SECRET_KEY", "dev-secret-key-change-me")
    
    # Network
    PROTECTED_IPS: List[str] = os.getenv("PROTECTED_IPS", "127.0.0.1,192.168.0.0/16,10.0.0.0/8").split(",")
    MALICIOUS_PORTS: set = set(map(int, os.getenv("MALICIOUS_PORTS", "1337,31337,12345,6667,6666,4444,5555,8080").split(",")))

config = Config()