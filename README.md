# AI-NGFW (AI-Powered Next Generation Firewall)

An advanced AI-powered network security solution that combines machine learning, federated learning, and Zero Trust architecture to provide real-time threat detection and automated response capabilities.

## Features

- **Real-time Packet Capture & Analysis**: Advanced traffic monitoring using Scapy
- **AI-Powered Threat Detection**: Machine learning models including Isolation Forest and LSTM-CNN
- **Federated Learning**: Collaborative threat intelligence across distributed networks
- **Zero Trust Security**: Dynamic risk scoring and adaptive access controls
- **Automated Response**: Intelligent threat blocking and response playbooks
- **Interactive Dashboard**: Real-time visualization and monitoring interface
- **Encrypted Traffic Analysis**: Advanced techniques for analyzing encrypted communications

## Architecture

### Backend (Python/FastAPI)
- Packet capture and traffic analysis
- ML-based anomaly detection
- Federated learning coordination
- Zero Trust risk assessment
- Automated threat response
- RESTful API and WebSocket endpoints

### Frontend (React/Vite)
- Real-time dashboard
- Threat visualization components
- Performance metrics panels
- Interactive security controls

### Infrastructure
- Docker containerization
- Automated setup scripts
- Comprehensive testing suite
- Detailed documentation

## Quick Start

1. **Setup Environment**
   ```bash
   ./scripts/setup.sh
   ```

2. **Start Backend**
   ```bash
   ./scripts/run_backend.sh
   ```

3. **Start Frontend**
   ```bash
   ./scripts/run_frontend.sh
   ```

4. **Access Dashboard**
   Open your browser to `http://localhost:3000`

## Documentation

- [Setup Instructions](docs/SETUP.md)
- [API Documentation](docs/API.md)
- [Demo Guide](docs/DEMO.md)

## License

See [LICENSE](LICENSE) file for details.

## Contributing

Please read our contributing guidelines before submitting pull requests.

