"""User-defined formats: a named-group regex or a pasted layout pattern, saved as JSON in the settings.

:class:`CustomFormat` is the editable, serialisable definition; :meth:`CustomFormat.to_format` validates it and builds
the :class:`LogFormat` used by detection and extraction. User formats win detection ties against built-ins.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .base import CANONICAL_LEVELS, CustomFormatError, LayoutError, LogFormat
from .layout import LAYOUT_STYLES, LayoutStyle, compile_layout

CUSTOM_PREFIX = "custom:"  # LogFormat names of user formats, so they never collide with built-in names
CUSTOM_PRIORITY = 1  # detection tie-break: a user format made for these files beats an equally good built-in
FORMAT_VERSION = 1  # bump when the JSON shape changes incompatibly

_STYLES: dict[str, LayoutStyle] = {style: style for style in LAYOUT_STYLES}
_TIME_NAMES = ("time", "timestamp", "datetime", "date", "ts")
_LEVEL_NAMES = ("level", "severity", "lvl", "loglevel", "priority")
_MESSAGE_NAMES = ("message", "msg", "text")


def _guess(names: tuple[str, ...], candidates: tuple[str, ...]) -> str:
    lowered = {name.lower(): name for name in names}
    return next((lowered[c] for c in candidates if c in lowered), "")


@dataclass(frozen=True, slots=True)
class CustomFormat:
    """A user format: ``regex`` (named groups become columns) or ``layout`` + ``style``; exactly one of the two.

    Empty ``time_field`` / ``level_field`` / ``message_field`` are guessed from the field names (``time``,
    ``timestamp`` …). ``level_map`` maps the format's own level tokens to canonical levels (``"E"`` → ``"Error"``).
    """

    name: str
    regex: str = ""
    layout: str = ""
    style: LayoutStyle = "auto"
    multiline: bool = False
    time_field: str = ""
    level_field: str = ""
    message_field: str = ""
    filename_hints: tuple[str, ...] = ()
    level_map: tuple[tuple[str, str], ...] = ()

    def _compiled(self) -> tuple[re.Pattern[str], tuple[str, ...], bool]:
        """(regex, field names, multiline) of the definition; raises :class:`CustomFormatError`."""
        if bool(self.regex.strip()) == bool(self.layout.strip()):
            raise CustomFormatError("give either a regex or a layout pattern")
        if self.layout.strip():
            if self.style not in LAYOUT_STYLES:
                raise CustomFormatError(f"unknown layout style {self.style!r}")
            try:
                compiled = compile_layout(self.layout, style=self.style)
            except LayoutError as error:
                raise CustomFormatError(f"layout: {error}") from error
            assert compiled.regex is not None  # compile_layout always builds a regex
            return compiled.regex, compiled.fields, True
        try:
            regex = re.compile(self.regex)
        except re.error as error:
            raise CustomFormatError(f"regex: {error}") from error
        if not regex.groupindex:
            raise CustomFormatError("the regex needs at least one named group, e.g. (?P<message>.*)")
        return regex, tuple(regex.groupindex), self.multiline

    def _role(self, given: str, names: tuple[str, ...], candidates: tuple[str, ...], role: str) -> str:
        if not given:
            return _guess(names, candidates)
        if given not in names:
            raise CustomFormatError(f"{role} field {given!r} is not one of the fields: {', '.join(names)}")
        return given

    def to_format(self) -> LogFormat:
        """The usable format; raises :class:`CustomFormatError` when the definition is invalid."""
        name = self.name.strip()
        if not name:
            raise CustomFormatError("the format needs a name")
        regex, fields, multiline = self._compiled()
        for token, level in self.level_map:
            if level not in CANONICAL_LEVELS:
                raise CustomFormatError(f"level {level!r} for {token!r} must be one of {', '.join(CANONICAL_LEVELS)}")
        return LogFormat(
            name=CUSTOM_PREFIX + name,
            display_name=name,
            fields=fields,
            regex=regex,
            multiline=multiline,
            time_field=self._role(self.time_field, fields, _TIME_NAMES, "time"),
            level_field=self._role(self.level_field, fields, _LEVEL_NAMES, "level"),
            message_field=self._role(self.message_field, fields, _MESSAGE_NAMES, "message"),
            level_map=MappingProxyType(dict(self.level_map)),
            filename_hints=self.filename_hints,
            priority=CUSTOM_PRIORITY,
            description=f"user format: {self.layout or self.regex}",
        )

    def validate(self) -> None:
        """Raise :class:`CustomFormatError` if the definition can't be used."""
        self.to_format()

    def to_dict(self) -> dict[str, object]:
        """JSON-serialisable form (for the settings file)."""
        data: dict[str, object] = {"version": FORMAT_VERSION, "name": self.name}
        if self.layout:
            data.update(layout=self.layout, style=self.style)
        else:
            data["regex"] = self.regex
        data.update(
            multiline=self.multiline,
            time_field=self.time_field,
            level_field=self.level_field,
            message_field=self.message_field,
            filename_hints=list(self.filename_hints),
            level_map=dict(self.level_map),
        )
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> CustomFormat:
        """Definition from :meth:`to_dict` output; raises :class:`CustomFormatError` for malformed data.

        Only the shape is checked here; call :meth:`validate` to check the regex / layout.
        """
        version = data.get("version", FORMAT_VERSION)
        if not isinstance(version, int) or version > FORMAT_VERSION:
            raise CustomFormatError(f"unsupported custom format version {version!r}")
        style_name = _text(data, "style") or "auto"
        style = _STYLES.get(style_name)
        if style is None:
            raise CustomFormatError(f"unknown layout style {style_name!r}")
        multiline = data.get("multiline", False)
        if not isinstance(multiline, bool):
            raise CustomFormatError("'multiline' must be true or false")
        return cls(
            name=_text(data, "name"),
            regex=_text(data, "regex"),
            layout=_text(data, "layout"),
            style=style,
            multiline=multiline,
            time_field=_text(data, "time_field"),
            level_field=_text(data, "level_field"),
            message_field=_text(data, "message_field"),
            filename_hints=_texts(data, "filename_hints"),
            level_map=_pairs(data, "level_map"),
        )


def _text(data: Mapping[str, object], key: str) -> str:
    value = data.get(key, "")
    if not isinstance(value, str):
        raise CustomFormatError(f"{key!r} must be text")
    return value


def _texts(data: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = data.get(key, [])
    if not isinstance(value, list | tuple) or not all(isinstance(item, str) for item in value):
        raise CustomFormatError(f"{key!r} must be a list of texts")
    return tuple(str(item) for item in value)


def _pairs(data: Mapping[str, object], key: str) -> tuple[tuple[str, str], ...]:
    value = data.get(key, {})
    if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        raise CustomFormatError(f"{key!r} must map texts to texts")
    return tuple(value.items())
