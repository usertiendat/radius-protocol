from pydantic import BaseModel, ConfigDict, Field, model_validator


class NASCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nasname: str = Field(min_length=1, max_length=128)
    shortname: str | None = Field(default=None, max_length=32)
    type: str = Field(default="other", max_length=30)
    secret: str = Field(min_length=1, max_length=60)


class NASUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nasname: str | None = Field(default=None, min_length=1, max_length=128)
    shortname: str | None = Field(default=None, max_length=32)
    type: str | None = Field(default=None, max_length=30)
    secret: str | None = Field(default=None, min_length=1, max_length=60)

    @model_validator(mode="after")
    def reject_null_required_fields(self):
        if "nasname" in self.model_fields_set and self.nasname is None:
            raise ValueError("nasname không được để trống")
        if "secret" in self.model_fields_set and self.secret is None:
            raise ValueError("secret không được để trống")
        return self


class NASResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    nasname: str
    shortname: str | None
    type: str | None
