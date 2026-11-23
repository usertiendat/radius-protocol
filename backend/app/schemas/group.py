from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator

Username = Annotated[str, Field(min_length=1, max_length=64)]


class GroupAttribute(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attribute: str = Field(min_length=1, max_length=64)
    op: str = Field(min_length=1, max_length=2)
    value: str = Field(max_length=253)


class GroupCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    groupname: str = Field(min_length=1, max_length=64)
    users: list[Username] = Field(default_factory=list)
    checks: list[GroupAttribute] = Field(default_factory=list)
    replies: list[GroupAttribute] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_persisted_group_data(self):
        if not (self.users or self.checks or self.replies):
            raise ValueError("Group phải có ít nhất một thành viên hoặc thuộc tính")
        return self


class GroupUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    users: list[Username] | None = None
    checks: list[GroupAttribute] | None = None
    replies: list[GroupAttribute] | None = None


class GroupResponse(BaseModel):
    groupname: str
    users: list[str]
    checks: list[GroupAttribute]
    replies: list[GroupAttribute]
