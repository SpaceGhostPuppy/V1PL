import asyncio
import aiohttp
import pika
import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
import ssl
from bs4 import BeautifulSoup
import re

# Datenklasse für Schwachstellen
@dataclass
class Vulnerability:
    name: str
    severity: str  # "low", "medium", "high", "critical"
    description: str
    url: str
    evidence: str
    remediation: str

# Datenklasse für Scan-Konfigurations Parameter
@dataclass
class ScanConfig:
  max_depth: int = 3
  rate_limit: float = 1.0 # Anfragen pro Sekunde
  timeout: int = 30
  verify_ssl = bool = True
  custom_headers: Dict[str, str] = None
  proxy: Optional[str] = None
  timeout: int = 30
  auth: Optional[Dict[str, str]] = None

class WebScanner:
  def __init__(self, amqp_url: str, config: ScanConfig):
    self.config = config
    self.vulnerabilities: List[Vulnerability] = []
    self.visited_urls: set = set()
    self.session = None
    self.rate_limiter = asyncio.Semaphore(1)
    self.logger = logging.getLogger("WebScanner")

    # Rabbit Verbindung hier aufbauen WIP
