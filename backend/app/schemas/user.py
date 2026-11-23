from datetime import datetime

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=253)
    fullname: str | None = Field(default=None, max_length=128)
    email: str | None = Field(default=None, max_length=255)


class UserUpdate(BaseModel):
    password: str | None = Field(default=None, min_length=1, max_length=253)
    fullname: str | None = Field(default=None, max_length=128)
    email: str | None = Field(default=None, max_length=255)


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    fullname: str | None = Field(
        default=None,
        validation_alias=AliasChoices("full_name", "fullname"),
    )
    email: str | None
    created_at: datetime
