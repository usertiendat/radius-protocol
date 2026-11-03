from pydantic import BaseModel, ConfigDict, Field


class NASCreate(BaseModel):
    nasname: str = Field(min_length=1, max_length=128)
    shortname: str | None = Field(default=None, max_length=32)
    type: str = Field(default="other", max_length=30)
    secret: str = Field(min_length=1, max_length=60)


class NASResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    nasname: str
    shortname: str | None
    type: str | None
