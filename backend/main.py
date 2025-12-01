from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
import uvicorn
import secrets
import ipaddress
from capture.packet_sniffer import packet_capture
from security.ip_blocker import ip_blocker
from config import config

security = HTTPBearer(auto_error=False)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Simple token-based auth for demo/hackathon"""
    if not config.API_AUTH_ENABLED:
        return True
    
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header"
        )
    
    if not secrets.compare_digest(credentials.credentials, config.API_SECRET_KEY):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid token"
        )
    
    return True


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for startup/shutdown"""
    # Startup
    packet_capture.start_capture()
    yield
    # Shutdown (cleanup if needed in future)

app = FastAPI(title="AI-NGFW Backend", lifespan=lifespan)


# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"message": "AI-NGFW Backend Running with Advanced Threat Detection!"}


@app.get("/api/stats")
def get_stats():
    stats = packet_capture.get_stats()
    cnn_stats = stats.get('cnn_stats', {})
    
    return {
        "total_packets": int(stats['total_packets']),
        "threats_detected": int(stats['threats_detected']),
        "ml_threats": int(stats['ml_threats']),
        "lstm_threats": int(stats.get('lstm_threats', 0)),
        "cnn_threats": int(stats.get('cnn_threats', 0)),
        "ml_trained": bool(stats['ml_trained']),
        "lstm_trained": bool(stats.get('lstm_stats', {}).get('is_trained', False)),
        "cnn_trained": bool(cnn_stats.get('is_trained', False)),
        "lstm_sequences_collected": int(stats.get('lstm_stats', {}).get('sequences_collected', 0)),
        "lstm_sequences_needed": int(stats.get('lstm_stats', {}).get('sequences_needed', 100)),
        "cnn_samples_collected": int(cnn_stats.get('samples_collected', 0)),
        "cnn_training_progress": int(cnn_stats.get('training_progress', 0)),
        "blocked_ips_count": len(ip_blocker.get_blocked_ips()),
        "threat_stats": stats.get('threat_stats', {}),
        "status": "running"
    }


@app.get("/api/packets")
def get_packets():
    stats = packet_capture.get_stats()
    return stats['recent_packets']


@app.get("/api/threats")
def get_threats():
    """Get recent threat packets - last 10 threats"""
    threats = packet_capture.threat_list
    
    clean_threats = []
    for threat in threats:
        clean_threat = {
            'id': int(threat.get('id', 0)),
            'src_ip': threat.get('src_ip', 'N/A'),
            'dst_ip': threat.get('dst_ip', 'N/A'),
            'src_port': int(threat.get('src_port', 0)) if threat.get('src_port') else None,
            'dst_port': int(threat.get('dst_port', 0)) if threat.get('dst_port') else None,
            'type': threat.get('type', 'OTHER'),
            'size': int(threat.get('size', 0)),
            'detection_method': threat.get('detection_method', 'Unknown'),
            'blocked': bool(threat.get('blocked', False)),
            'severity': threat.get('severity', 'LOW'),
            'threat_types': threat.get('threat_types', []),
            'mitre_tactics': threat.get('mitre_tactics', []),
            'timestamp': float(threat.get('timestamp', 0))
        }
        clean_threats.append(clean_threat)
    
    return clean_threats


@app.get("/api/threat-stats")
def get_threat_stats():
    """Get detailed threat statistics by category"""
    stats = packet_capture.get_stats()
    threat_stats = stats.get('threat_stats', {})
    
    return {
        "categories": {
            "ddos": threat_stats.get('ddos', 0),
            "port_scan": threat_stats.get('port_scan', 0),
            "malware": threat_stats.get('malware', 0),
            "sql_injection": threat_stats.get('sql_injection', 0),
            "xss": threat_stats.get('xss', 0),
            "command_injection": threat_stats.get('command_injection', 0),
            "directory_traversal": threat_stats.get('directory_traversal', 0)
        },
        "total_advanced_threats": sum(threat_stats.values()),
        "most_common": max(threat_stats.items(), key=lambda x: x[1])[0] if threat_stats else "none"
    }


@app.get("/api/lstm-stats")
def get_lstm_stats():
    """Get detailed LSTM training and detection statistics"""
    stats = packet_capture.get_stats()
    lstm_stats = stats.get('lstm_stats', {})
    
    return {
        "is_trained": lstm_stats.get('is_trained', False),
        "sequences_collected": lstm_stats.get('sequences_collected', 0),
        "sequences_needed": lstm_stats.get('sequences_needed', 100),
        "sequence_length": lstm_stats.get('sequence_length', 10),
        "training_progress": min(100, int((lstm_stats.get('sequences_collected', 0) / 100) * 100)),
        "lstm_threats_detected": int(stats.get('lstm_threats', 0)),
        "status": "trained" if lstm_stats.get('is_trained', False) else "collecting_data"
    }


@app.get("/api/cnn-stats")
def get_cnn_stats():
    """Get detailed CNN training and detection statistics"""
    stats = packet_capture.get_stats()
    cnn_stats = stats.get('cnn_stats', {})
    
    return {
        "cnn_trained": cnn_stats.get('is_trained', False),
        "samples_collected": cnn_stats.get('samples_collected', 0),
        "samples_needed": cnn_stats.get('samples_needed', 200),
        "training_progress": cnn_stats.get('training_progress', 0),
        "model_parameters": cnn_stats.get('model_params', 0),
        "cnn_threats_detected": int(stats.get('cnn_threats', 0)),
        "status": "trained" if cnn_stats.get('is_trained', False) else "collecting_data"
    }


@app.get("/api/mitre-mapping")
def get_mitre_mapping():
    """Get MITRE ATT&CK framework mappings for detected threats"""
    from models.advanced_threats import MITRE_MAPPING
    return {
        "mappings": MITRE_MAPPING,
        "framework_version": "v14",
        "url": "https://attack.mitre.org/"
    }


@app.get("/api/blocked-ips")
def get_blocked_ips():
    """Get list of blocked IPs"""
    return {
        "blocked_ips": ip_blocker.get_blocked_ips(),
        "count": len(ip_blocker.get_blocked_ips())
    }


@app.post("/api/block-ip/{ip_address}", dependencies=[Depends(verify_token)])
def block_ip_manual(ip_address: str):
    """Manually block an IP"""
    # Validate IP address
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    
    success = ip_blocker.block_ip(ip_address)
    return {
        "success": success,
        "ip": ip_address,
        "message": f"IP {ip_address} {'blocked' if success else 'could not be blocked'}"
    }


@app.post("/api/unblock-ip/{ip_address}", dependencies=[Depends(verify_token)])
def unblock_ip_manual(ip_address: str):
    """Manually unblock an IP"""
    # Validate IP address
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    
    success = ip_blocker.unblock_ip(ip_address)
    return {
        "success": success,
        "ip": ip_address,
        "message": f"IP {ip_address} {'unblocked' if success else 'could not be unblocked'}"
    }


@app.post("/api/unblock-all", dependencies=[Depends(verify_token)])
def unblock_all_ips():
    """Unblock all blocked IPs"""
    blocked_ips = ip_blocker.get_blocked_ips().copy()
    unblocked = []
    failed = []
    
    for ip in blocked_ips:
        success = ip_blocker.unblock_ip(ip)
        if success:
            unblocked.append(ip)
        else:
            failed.append(ip)
    
    return {
        "unblocked": unblocked,
        "failed": failed,
        "message": f"Unblocked {len(unblocked)} IPs, failed: {len(failed)}"
    }


if __name__ == "__main__":
    uvicorn.run(app, host=config.API_HOST, port=config.API_PORT)
