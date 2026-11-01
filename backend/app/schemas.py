from ipaddress import ip_address

from pydantic import BaseModel, ConfigDict, Field, field_validator


class GroupSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=1, max_length=256)
    email: str | None = Field(default=None, max_length=255)
    is_active: bool = True
    group_ids: list[int] = Field(default_factory=list)


class UserUpdate(BaseModel):
    username: str | None = Field(default=None, min_length=1, max_length=100)
    password: str | None = Field(default=None, min_length=1, max_length=256)
    email: str | None = Field(default=None, max_length=255)
    is_active: bool | None = None
    group_ids: list[int] | None = None


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str | None
    is_active: bool
    groups: list[GroupSummary]


class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)


class GroupUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)


class GroupRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    users_count: int


class NASCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    ip_address: str = Field(min_length=1, max_length=45)
    shared_secret: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=500)
    is_active: bool = True

    @field_validator("ip_address")
    @classmethod
    def normalize_ip_address(cls, value: str) -> str:
        return str(ip_address(value))


class NASUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    ip_address: str | None = Field(default=None, min_length=1, max_length=45)
    shared_secret: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=500)
    is_active: bool | None = None

    @field_validator("ip_address")
    @classmethod
    def normalize_ip_address(cls, value: str | None) -> str | None:
        return str(ip_address(value)) if value is not None else None


class NASRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    ip_address: str
    description: str | None
    is_active: bool
