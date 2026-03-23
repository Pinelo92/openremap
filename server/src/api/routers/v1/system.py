from fastapi import APIRouter, Request

from api.core.limiter import ApiLimits, limiter

router = APIRouter()


@router.get("/status")
@limiter.limit(ApiLimits.READ)
async def get_status(request: Request):
    """
    Get the current status of the system.
    """
    # Placeholder for actual status retrieval logic
    return {"status": "ok", "message": "System is running smoothly."}
