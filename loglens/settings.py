"""Persistent user settings (JSON in %APPDATA%\\LogLens\\settings.json)."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from .core.ai.config import AIConfig
from .core.formats import CustomFormat, CustomFormatError
from .core.highlight import HighlightRule, default_rules
from .core.packs import PackError, SavedFilter
from .core.watch import AlertRule, WatchProfile, default_alert_rules
from .core.winevent.remote import ServerProfile
from .paths import settings_file

log = logging.getLogger(__name__)
MAX_RECENT = 15


@dataclass
class Settings:
    recent_files: list[str] = field(default_factory=list)
    last_dir: str = ""
    font_family: str = ""
    font_size: int = 10
    tab_width: int = 4
    follow_by_default: bool = False
    theme: str = "system"  # system | light | dark
    word_wrap: bool = False
    web_search_engine: str = "Google"
    window_geometry: str = ""
    window_state: str = ""
    highlight_rules: list[dict] = field(default_factory=lambda: [r.to_dict() for r in default_rules()])
    rules_customized: bool = False  # False: always use the built-in defaults (they improve with updates)
    show_inspector: bool = True
    show_timeline: bool = True
    mask_secrets: bool = False
    context_lines: int = 0
    ai: dict = field(default_factory=dict)
    search_history: list[str] = field(default_factory=list)
    saved_filter_list: list[dict] = field(default_factory=list)
    alert_rule_list: list[dict] = field(default_factory=lambda: [r.to_dict() for r in default_alert_rules()])
    watch_profile_list: list[dict] = field(default_factory=list)
    run_in_tray: bool = False
    watched_services: list[str] = field(default_factory=list)
    custom_format_list: list[dict] = field(default_factory=list)
    server_list: list[dict] = field(default_factory=list)  # other Windows servers (no passwords here)

    # ---- convenience ---------------------------------------------------------------------------------------------
    def rules(self) -> list[HighlightRule]:
        """Saved rules if the user customised them, otherwise the current built-in defaults."""
        if not self.rules_customized:
            return default_rules()
        return [HighlightRule.from_dict(d) for d in self.highlight_rules]

    def set_rules(self, rules: list[HighlightRule]) -> None:
        self.highlight_rules = [r.to_dict() for r in rules]
        self.rules_customized = True

    def saved_filters(self) -> list[SavedFilter]:
        out = []
        for data in self.saved_filter_list:
            try:
                out.append(SavedFilter.from_dict(data))
            except PackError as exc:
                log.warning("Skipping invalid saved filter: %s", exc)
        return out

    def set_saved_filters(self, filters: list[SavedFilter]) -> None:
        self.saved_filter_list = [f.to_dict() for f in filters]

    def alert_rules(self) -> list[AlertRule]:
        out = []
        for data in self.alert_rule_list:
            try:
                out.append(AlertRule.from_dict(data))
            except (KeyError, TypeError, ValueError) as exc:
                log.warning("Skipping invalid alert rule: %s", exc)
        return out

    def set_alert_rules(self, rules: list[AlertRule]) -> None:
        self.alert_rule_list = [r.to_dict() for r in rules]

    def watch_profiles(self) -> list[WatchProfile]:
        out = []
        for data in self.watch_profile_list:
            try:
                out.append(WatchProfile.from_dict(data))
            except (KeyError, TypeError) as exc:
                log.warning("Skipping invalid watch profile: %s", exc)
        return out

    def set_watch_profiles(self, profiles: list[WatchProfile]) -> None:
        self.watch_profile_list = [p.to_dict() for p in profiles]

    def servers(self) -> list[ServerProfile]:
        """The saved servers (entries that are no longer valid, e.g. hand-edited, are skipped)."""
        found = (ServerProfile.from_dict(data) for data in self.server_list if isinstance(data, dict))
        return [profile for profile in found if profile is not None]

    def set_servers(self, servers: list[ServerProfile]) -> None:
        self.server_list = [s.to_dict() for s in servers]

    def custom_formats(self) -> list[CustomFormat]:
        out = []
        for data in self.custom_format_list:
            try:
                out.append(CustomFormat.from_dict(data))
            except CustomFormatError as exc:
                log.warning("Skipping invalid custom format: %s", exc)
        return out

    def set_custom_formats(self, formats: list[CustomFormat]) -> None:
        self.custom_format_list = [f.to_dict() for f in formats]

    def ai_config(self) -> AIConfig:
        return AIConfig.from_dict(self.ai)

    def set_ai_config(self, config: AIConfig) -> None:
        self.ai = config.to_dict()

    def add_recent(self, path: str) -> None:
        path = str(Path(path))
        self.recent_files = [p for p in self.recent_files if p.lower() != path.lower()]
        self.recent_files.insert(0, path)
        del self.recent_files[MAX_RECENT:]
        self.last_dir = str(Path(path).parent)

    def add_search(self, text: str) -> None:
        self.search_history = [t for t in self.search_history if t != text]
        self.search_history.insert(0, text)
        del self.search_history[30:]

    # ---- persistence ---------------------------------------------------------------------------------------------
    @classmethod
    def load(cls, path: Path | None = None) -> Settings:
        path = path or settings_file()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls()
        except (OSError, ValueError) as exc:
            log.warning("Could not read settings %s: %s", path, exc)
            return cls()
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    def save(self, path: Path | None = None) -> None:
        path = path or settings_file()
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        tmp.replace(path)
