from motor.motor_asyncio import AsyncIOMotorClient

from src.core.config import settings
from src.core.logger import get_logger

logger = get_logger("database", file_output=True)

# Create MongoDB client
logger.info(
    f"Initializing MongoDB client with URL: {settings.MONGO_URL.split('@')[-1]}"
)  # Hide credentials
client = AsyncIOMotorClient(settings.MONGO_URL)

# Get database based on environment
database = client[settings.database_name]
logger.info(
    f"Connected to database: {settings.database_name} (Environment: {settings.APP_ENV})"
)
