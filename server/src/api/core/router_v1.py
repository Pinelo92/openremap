from fastapi import APIRouter
from api.routers.v1.system import router as system_router
from api.routers.v1.tuning import router as tuning_router

router_v1 = APIRouter(prefix="/api/v1")


router_v1.include_router(
    prefix="/system",
    tags=["System"],
    router=system_router,
)

router_v1.include_router(
    prefix="/tuning",
    tags=["Tuning"],
    router=tuning_router,
)
