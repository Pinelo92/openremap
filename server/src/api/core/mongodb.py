from motor.motor_asyncio import AsyncIOMotorClient

from api.core.config import settings
from api.core.logger import get_logger

logger = get_logger("database", file_output=True)

# Create MongoDB client
logger.info(
    f"Initializing MongoDB client with URL: {settings.MONGO_URL.split('@')[-1]}"
)  # Hide credentials
client = AsyncIOMotorClient(settings.MONGO_URL)

# Get database based on environment — Motor is lazy: no socket is opened here.
# The actual TCP connection is deferred until the first query or ping.
database = client[settings.database_name]
logger.info(
    f"Database handle created: {settings.database_name} "
    f"(Environment: {settings.APP_ENV}) — connection not yet verified"
)
