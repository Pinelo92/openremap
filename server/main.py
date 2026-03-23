from fastapi import FastAPI
from api.core.bootstrap import setup_app
from api.core.lifespan import lifespan
from api.core.config import settings

# 1. Instantiate the app with the modular lifespan
app = FastAPI(title=settings.APP_NAME, lifespan=lifespan)

# 2. Setup configuration, routes, and error handlers
setup_app(app)
