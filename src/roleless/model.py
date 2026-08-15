from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Role = Literal["viewer", "agent", "supervisor", "admin", "contractor"]


class Actor(BaseModel):
    id: str
    name: str
    role: Role


class TicketCreate(BaseModel):
    subject: str = Field(min_length=1, max_length=120)
    assignee_id: str


class CommentCreate(BaseModel):
    body: str = Field(min_length=1, max_length=500)


class ReassignRequest(BaseModel):
    assignee_id: str


class RoleGrant(BaseModel):
    role: Role
