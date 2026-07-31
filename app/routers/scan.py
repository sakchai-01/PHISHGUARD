from fastapi import APIRouter, Depends, HTTPException, status
from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.scan import ScanRequest, ScanResponse
from app.db.session import get_db
from app.services.scan_service import ScanService

router = APIRouter(prefix="/scan", tags=["scan"])

@router.post("/", response_model=ScanResponse)
async def scan_url(
    request: ScanRequest,
    db: AsyncSession = Depends(get_db)
) -> Any:
    """
    Scan a URL for phishing threats using the ScanService.
    """
    try:
        service = ScanService(db)
        return await service.scan_url(str(request.url))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error analyzing URL: {str(e)}"
        )
