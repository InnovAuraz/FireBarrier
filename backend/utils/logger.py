import sys
from loguru import logger
from config import config

# Remove default handler
logger.remove()

# Add custom handlers
logger.add(
    sys.stdout,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    level="INFO"
)

logger.add(
    "data/logs/firebarrier_{time:YYYY-MM-DD}.log",
    rotation="00:00",  # New file daily
    retention="30 days",
    compression="zip",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
    level="DEBUG"
)

# Structured logging helper
def log_threat(packet_info: dict, detection_method: str, severity: str):
    logger.warning(
        f"THREAT_DETECTED | method={detection_method} | severity={severity} | "
        f"src={packet_info.get('src_ip')} | dst={packet_info.get('dst_ip')} | "
        f"port={packet_info.get('dst_port')}"
    )

def log_block(ip: str, reason: str):
    logger.critical(f"IP_BLOCKED | ip={ip} | reason={reason}")