import pytest
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from config import Config


class TestConfig:
    def test_config_loads_defaults(self):
        config = Config()
        assert config.THREAT_THRESHOLD == 10
        assert config.LSTM_PREDICTION_THRESHOLD == 0.5
        assert config.ISOLATION_CONTAMINATION == 0.15
        assert config.DDOS_THRESHOLD == 100
        assert config.PORT_SCAN_THRESHOLD == 10
    
    def test_config_training_defaults(self):
        config = Config()
        assert config.ISOLATION_TRAIN_AT == 50
        assert config.LSTM_MIN_SEQUENCES == 100
        assert config.LSTM_SEQUENCE_LENGTH == 10
    
    def test_config_api_defaults(self):
        config = Config()
        assert config.API_HOST == "0.0.0.0"
        assert config.API_PORT == 8000
        assert isinstance(config.CORS_ORIGINS, list)
    
    def test_config_network_settings(self):
        config = Config()
        assert isinstance(config.PROTECTED_IPS, list)
        assert isinstance(config.MALICIOUS_PORTS, set)
        assert len(config.MALICIOUS_PORTS) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
