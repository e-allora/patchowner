import uuid
from datetime import date, datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

class Base(DeclarativeBase):
    """Base declarative class for SQLAlchemy models."""

    pass

# 1. TENANTS & ORGANIZATIONS
class Tenant(Base):
    __tablename__ = "tenants"

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    domain: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    users: Mapped[List["User"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )
    assets: Mapped[List["Asset"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )
    policies: Mapped[List["Policy"]] = relationship(
        back_populates="tenant", cascade="all, delete-orphan"
    )

# 2. USERS & IDENTITY DIRECTORY SYNC
class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        Index("idx_users_tenant_email", "tenant_id", "email", unique=True),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # 'admin', 'fixer', 'accountable', 'escalation'
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    tenant: Mapped["Tenant"] = relationship(back_populates="users")

# 3. ASSETS (Evolved from inventory.csv)
class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        Index("idx_assets_tenant_status", "tenant_id", "status"),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_name: Mapped[str] = mapped_column(String(255), nullable=False)
    vendor: Mapped[str] = mapped_column(String(255), nullable=False)
    product: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    environment: Mapped[str] = mapped_column(
        String(50), default="production"
    )  # 'production', 'staging', 'test'
    internet_exposed: Mapped[bool] = mapped_column(Boolean, default=False)
    criticality: Mapped[str] = mapped_column(
        String(50), default="medium"
    )  # 'low', 'medium', 'high', 'critical'

    # SSVC Explicit Overrides
    ssvc_exposure_override: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # 'small', 'controlled', 'open'
    ssvc_human_impact_override: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )  # 'low', 'medium', 'high', 'very high'

    # Ownership & Routing Contacts
    owner_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=True
    )
    accountable_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=True
    )
    oncall_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=True
    )
    escalate_to_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=True
    )

    # Exception & Lifecycle Tracking
    status: Mapped[str] = mapped_column(
        String(50), default="active"
    )  # 'active', 'retired'
    exception_until: Mapped[Optional[date]] = mapped_column(
        Date, nullable=True
    )
    exception_reason: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    tenant: Mapped["Tenant"] = relationship(back_populates="assets")

# 4. GLOBAL ADVISORIES & VULNERABILITIES (Shared Across Tenants)
class Advisory(Base):
    __tablename__ = "advisories"

    advisory_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cve_id: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False, index=True
    )  # e.g., 'CVE-2026-1284'
    source: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # 'CISA_KEV', 'NVD', 'VENDOR'
    vendor: Mapped[str] = mapped_column(String(255), nullable=False)
    product: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    exploitation_state: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # 'none', 'public_poc', 'active'
    automatable: Mapped[str] = mapped_column(
        String(50), default="yes"
    )  # 'no', 'yes'
    published_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

# 5. POLICIES & SSVC DECISION TREES
class Policy(Base):
    __tablename__ = "policies"

    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    level: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # 'platform', 'org', 'bu', 'team', 'asset'
    ssvc_tree_rules: Mapped[Dict[str, Any]] = mapped_column(
        JSONB, nullable=False
    )  # SEI SSVC 2.0 decision matrix
    sla_windows: Mapped[Dict[str, Any]] = mapped_column(
        JSONB, nullable=False
    )  # Acknowledge, Plan, Escalate hours per urgency
    alert_budgets: Mapped[Dict[str, Any]] = mapped_column(
        JSONB, nullable=False
    )  # Max urgent notices per week
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    tenant: Mapped["Tenant"] = relationship(back_populates="policies")

# 6. MATCHED NOTICES & ROUTING DISPATCHES
class Notice(Base):
    __tablename__ = "notices"
    __table_args__ = (
        Index("idx_notices_tenant_urgency", "tenant_id", "urgency"),
    )

    notice_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assets.asset_id", ondelete="CASCADE"),
        nullable=False,
    )
    advisory_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("advisories.advisory_id", ondelete="CASCADE"),
        nullable=False,
    )
    match_confidence: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # 'exact', 'likely', 'possible'

    # Evaluated SSVC Decision Output
    urgency: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # 'Act now', 'Update soon', 'Plan update', 'Defer'
    ssvc_vector: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # e.g., 'SSVCv2/A:Y/E:A/H:H/Se:O/'
    one_sentence_reason: Mapped[str] = mapped_column(Text, nullable=False)

    # Suppression Metadata
    is_suppressed: Mapped[bool] = mapped_column(Boolean, default=False)
    suppression_reason: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # 'retired', 'active_exception', 'policy_defer'

    # SLA Deadlines
    ack_deadline: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    plan_deadline: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    escalation_deadline: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

# 7. ACTION HISTORY & AUDIT TRAIL
class ActionState(Base):
    __tablename__ = "action_states"
    __table_args__ = (
        Index("idx_action_states_tenant_notice", "tenant_id", "notice_id"),
    )

    action_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    notice_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("notices.notice_id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=False
    )
    action: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # 'open_fix', 'acknowledge', 'assign', 'does_not_apply', 'fixed'
    assigned_to_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=True
    )
    comment: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
