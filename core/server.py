"""
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient

from settings import Settings


settings = Settings()
app = FastAPI()

origins = [
    "http://localhost",
    "http://localhost:8080",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Create Motor client
client = AsyncIOMotorClient(settings.MASTER_DB_MONGO_URI)

@app.get("/")
def root():
    """
    Root endpoint.
    TODO: Will remove this later.
    """
    return {"message": "It's not just a nap, it's a POWER nap."}
