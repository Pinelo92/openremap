from fastapi import FastAPI
from src.core.bootstrap import setup_app
from src.core.lifespan import lifespan
from src.core.config import settings

# 1. Instantiate the app with the modular lifespan
app = FastAPI(title=settings.APP_NAME, lifespan=lifespan)

# 2. Setup configuration, routes, and error handlers
setup_app(app)
