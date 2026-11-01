"""Plain-text notification messages (FR-NTF-004).

Only sanitized fields: organization, project and monitor display names, display host, state,
times, a failure category/HTTP status and an incident reference link (which requires sign-in).
Never URLs with query strings, headers, bodies, IPs, notes or member details.
"""

from dataclasses import dataclass
from datetime import datetime

from sentinelops.notifications.models import NotifyEvent

TYPE_TITLES = {"OUTAGE": "Outage", "TLS_EXPIRY": "TLS certificate expiry"}


@dataclass(frozen=True)
class MessageContext:
    event_type: str
    organization_name: str
    link: str
    channel_label: str = ""
    project_name: str | None = None
    monitor_name: str | None = None
    hostname: str | None = None
    incident_type: str | None = None
    severity: str | None = None
    opened_at: datetime | None = None
    resolved_at: datetime | None = None
    failure_category: str | None = None
    http_status: int | None = None
    tls_days_remaining: int | None = None
    tls_threshold_days: int | None = None
    resolution: str | None = None


@dataclass(frozen=True)
class Message:
    subject: str
    text: str


def _time(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC") if value else "—"


def _duration(seconds: int) -> str:
    minutes = seconds // 60
    if minutes < 1:
        return f"{seconds} s"
    if minutes < 120:
        return f"{minutes} min"
    return f"{minutes // 60} h {minutes % 60} min"


def _where(c: MessageContext) -> list[str]:
    lines = [f"Organization: {c.organization_name}"]
    if c.project_name:
        lines.append(f"Project: {c.project_name}")
    if c.hostname:
        lines.append(f"Host: {c.hostname}")
    return lines


def render(c: MessageContext) -> Message:
    kind = TYPE_TITLES.get(c.incident_type or "", "Incident")
    name = c.monitor_name or "monitor"
    if c.event_type == NotifyEvent.CHANNEL_TEST:
        return Message(
            "SentinelOps test notification",
            f"SentinelOps test notification for {c.organization_name} "
            f"(channel: {c.channel_label}). Alerts for routed events will arrive here.",
        )
    if c.event_type == NotifyEvent.MONITOR_AUTO_PAUSED:
        lines = [
            f"[ACTION NEEDED] Monitor paused by policy: {name}",
            *_where(c),
            "Three consecutive checks were blocked by the destination policy, so monitoring "
            "was paused. Review the monitor and its domain.",
            f"Monitor: {c.link}",
        ]
        return Message(f"Monitor paused by policy: {name}", "\n".join(lines))
    if c.event_type == NotifyEvent.INCIDENT_RESOLVED:
        how = "manually" if c.resolution == "MANUAL" else "automatically"
        lines = [f"[RESOLVED] {kind} resolved {how}: {name}", *_where(c)]
        lines.append(f"Opened: {_time(c.opened_at)}")
        lines.append(f"Resolved: {_time(c.resolved_at)}")
        if c.opened_at and c.resolved_at:
            estimate = " (estimated)" if c.incident_type == "OUTAGE" else ""
            seconds = int((c.resolved_at - c.opened_at).total_seconds())
            lines.append(f"Duration{estimate}: {_duration(seconds)}")
        lines.append(f"Incident: {c.link}")
        return Message(f"[RESOLVED] {kind}: {name}", "\n".join(lines))
    if c.event_type == NotifyEvent.INCIDENT_ACKNOWLEDGED:
        lines = [f"[ACKNOWLEDGED] {kind}: {name}", *_where(c)]
        lines.append(f"Opened: {_time(c.opened_at)}")
        lines.append("A team member acknowledged this incident.")
        lines.append(f"Incident: {c.link}")
        return Message(f"[ACKNOWLEDGED] {kind}: {name}", "\n".join(lines))
    # INCIDENT_OPENED / TLS_EXPIRY_WARNING
    severity = c.severity or "WARNING"
    lines = [f"[{severity}] {kind}: {name}", *_where(c)]
    if c.tls_days_remaining is not None:
        lines.append(
            f"Certificate expires in {c.tls_days_remaining} days "
            f"(warning threshold {c.tls_threshold_days} days)."
        )
    elif c.failure_category or c.http_status:
        summary = c.failure_category or "FAILED"
        if c.http_status:
            summary += f" (HTTP {c.http_status})"
        lines.append(f"Problem: {summary}")
    lines.append(f"Opened: {_time(c.opened_at)}")
    lines.append(f"Incident: {c.link}")
    return Message(f"[{severity}] {kind}: {name}", "\n".join(lines))
