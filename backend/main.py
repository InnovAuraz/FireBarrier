from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from capture.packet_sniffer import packet_capture
from security.ip_blocker import ip_blocker

app = FastAPI(title="AI-NGFW Backend")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Start packet capture when app starts
@app.on_event("startup")
def startup_event():
    packet_capture.start_capture()

@app.get("/")
def read_root():
    return {"message": "AI-NGFW Backend Running with Advanced Threat Detection!"}

@app.get("/api/stats")
def get_stats():
    stats = packet_capture.get_stats()
    return {
        "total_packets": int(stats['total_packets']),
        "threats_detected": int(stats['threats_detected']),
        "ml_threats": int(stats['ml_threats']),
        "lstm_threats": int(stats.get('lstm_threats', 0)),  # NEW
        "ml_trained": bool(stats['ml_trained']),
        "lstm_trained": bool(stats.get('lstm_stats', {}).get('is_trained', False)),  # NEW
        "lstm_sequences_collected": int(stats.get('lstm_stats', {}).get('sequences_collected', 0)),  # NEW
        "lstm_sequences_needed": int(stats.get('lstm_stats', {}).get('sequences_needed', 100)),  # NEW
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
            'detection_method': threat.get('detection_method', 'Unknown'),  # Will include "LSTM"
            'blocked': bool(threat.get('blocked', False)),
            'severity': threat.get('severity', 'LOW'),
            'threat_types': threat.get('threat_types', []),  # Will include "Sequential Pattern"
            'timestamp': float(threat.get('timestamp', 0))
        }
        clean_threats.append(clean_threat)
    
    return clean_threats

# NEW: Threat Statistics by Category
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


# Blocked IPs endpoints
@app.get("/api/blocked-ips")
def get_blocked_ips():
    """Get list of blocked IPs"""
    return {
        "blocked_ips": ip_blocker.get_blocked_ips(),
        "count": len(ip_blocker.get_blocked_ips())
    }

@app.post("/api/block-ip/{ip_address}")
def block_ip_manual(ip_address: str):
    """Manually block an IP"""
    success = ip_blocker.block_ip(ip_address)
    return {
        "success": success,
        "ip": ip_address,
        "message": f"IP {ip_address} {'blocked' if success else 'could not be blocked'}"
    }

@app.post("/api/unblock-ip/{ip_address}")
def unblock_ip_manual(ip_address: str):
    """Manually unblock an IP"""
    success = ip_blocker.unblock_ip(ip_address)
    return {
        "success": success,
        "ip": ip_address,
        "message": f"IP {ip_address} {'unblocked' if success else 'could not be unblocked'}"
    }

@app.post("/api/unblock-all")
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
    uvicorn.run(app, host="0.0.0.0", port=8000)
