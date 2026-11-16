"""Unit tests for soc_triage/ui_style.py (the stylesheet string)."""

import re

from soc_triage import ui_present
from soc_triage.ui_style import UI_CSS


def test_stylesheet_is_a_non_empty_string():
    assert isinstance(UI_CSS, str) and len(UI_CSS.strip()) > 100


def test_braces_are_balanced():
    assert UI_CSS.count("{") == UI_CSS.count("}")


def test_every_class_the_presentation_helpers_emit_has_a_rule():
    source = open(ui_present.__file__, encoding="utf-8").read()
    emitted = set(re.findall(r'class="(soc-[a-z-]+)', source))
    missing = {name for name in emitted if f".{name}" not in UI_CSS}
    assert not missing, f"classes emitted by ui_present but not styled: {sorted(missing)}"
