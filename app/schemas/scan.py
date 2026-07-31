from pydantic import BaseModel, HttpUrl
from typing import List, Optional

class ScanRequest(BaseModel):
    url: HttpUrl

class ScanResultDetails(BaseModel):
    threat_level: str
    category: str
    target_brand: Optional[str] = None
    official_url: Optional[str] = None
    reasons: List[str] = []

class ScanResponse(BaseModel):
    status: str
    site_name: str
    message: str
    risk_score: int
    details: ScanResultDetails
