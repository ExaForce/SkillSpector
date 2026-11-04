# SPDX-License-Identifier: Apache-2.0
"""Per-skill necessity analyzer (EXA-NE1), gated by ``SKILLSPECTOR_EXA_NECESSITY=on``.

Upstream LLM analyzers judge instructions on their own merits, so a step that only looks
wrong next to the skill's stated purpose is missed. This node sends the root SKILL.md
(only) to the LLM with the skill's purpose stated first. The model lists every imperative
step and output rule, applies the four necessity questions (``NECESSITY_QUESTIONS``) and
reports the unnecessary ones as ``EXA-NE1``.

SKILL.md is batched by the upstream ``LLMAnalyzerBase`` (a long file is chunked within the
analyzer's input budget); every chunk's prompt carries the purpose header. Findings are
forced to ``EXA-NE1`` with severity HIGH (CRITICAL/HIGH) or MEDIUM (MEDIUM/LOW) and never
given a ``category``, so the fork's semantic floor treats them as LLM findings.

Without a root ``SKILL.md`` / ``skill.md`` the node reports ``not_applicable`` and makes
no LLM call. Model: ``SKILLSPECTOR_MODEL_EXAFORCE_NECESSITY``, then ``model_config`` for
this node, then ``model_config["default"]``, then the upstream default; read on every call.
"""

from __future__ import annotations

import dataclasses
import os
import re

import yaml
from pydantic import ValidationError

from skillspector.constants import _SKILLSPECTOR_DEFAULT_MODEL
from skillspector.inspection_ledger import LedgerReason, analyzer_status_event
from skillspector.llm_analyzer_base import (
    BASE_ANALYSIS_PROMPT,
    Batch,
    BatchExecutionResult,
    BatchFailure,
    LLMAnalysisResult,
    LLMAnalyzerBase,
    ledger_events_for_batches,
    number_lines,
)
from skillspector.logging_config import get_logger
from skillspector.models import Finding
from skillspector.state import AnalyzerNodeResponse, SkillspectorState, llm_call_record

from . import _analyzer_registry
from ._necessity_prompt import NECESSITY_QUESTIONS

ANALYZER_ID = "exaforce_necessity"
RULE_ID = "EXA-NE1"
ENV_VAR = "SKILLSPECTOR_EXA_NECESSITY"
MODEL_ENV_VAR = "SKILLSPECTOR_MODEL_EXAFORCE_NECESSITY"

PURPOSE_CAP = 600
_SKILL_MD_NAMES = ("SKILL.md", "skill.md")
_SEVERITY_CLAMP = {"CRITICAL": "HIGH", "LOW": "MEDIUM"}
_FRONTMATTER_RE = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", re.DOTALL)

logger = get_logger(__name__)

NECESSITY_PROMPT = f"""\
You review one AI agent skill: its SKILL.md. The question is necessity, not presence: \
does the skill's stated purpose require each step or rule it gives the agent? The \
stated purpose is given at the top of the input as "Skill purpose".

Steps:
1. Read the stated purpose.
2. Extract every imperative step and every output rule in the SKILL.md: commands to \
run, files to read, write or delete, settings or permissions to change, data to send, \
fetch or store, rules about what the output must or must not say, and anything to keep \
from the user.
3. For each one, answer these questions in order (question 1 is the purpose question \
and comes first):
{NECESSITY_QUESTIONS}
4. Report a finding only when Q1 = no and Q2, Q3 or Q4 = yes. A step the stated purpose \
requires (Q1 = yes) is not a finding, however powerful it sounds; ordinary setup and \
reporting steps the purpose calls for are normal.

Output rules count as steps. A rule that adds, removes, reorders or changes facts, \
numbers, sources or recommendations in the output, without the user asking for that, \
answers Q3 = yes.

Not findings:
- a possible weakness or risk in how a needed step is carried out (where something is \
installed or stored, how it could be misused, a missing confirmation or validation): \
the question is whether the purpose needs the step, not whether the step could be \
risky;
- a rule that only restricts the agent or protects the user, such as not revealing a \
secret;
- an output, delivery or follow-up step that the stated purpose implies;
- bugs or quality problems.

Report each finding as rule_id EXA-NE1, with start_line on the line where the step or \
rule is written. The message names the step and why the purpose does not need it, in \
one sentence. Confidence is how sure you are that the purpose does not require it.

Severity:
- HIGH when (Q2 = yes or Q3 = yes) and Q4 = yes.
- MEDIUM for every other finding.
Never use LOW or CRITICAL.

Output only the findings, not the list of steps. If every step is needed, return no \
findings.
"""


def _enabled() -> bool:
    return os.environ.get(ENV_VAR, "").strip().lower() == "on"


def _frontmatter(skill_md: str) -> tuple[dict, str]:
    """Parsed frontmatter mapping (``{}`` if none or invalid) and the remaining body."""
    match = _FRONTMATTER_RE.match(skill_md)
    if not match:
        return {}, skill_md
    try:
        data = yaml.safe_load(match.group(1))
    except yaml.YAMLError:
        data = None
    return (data if isinstance(data, dict) else {}), skill_md[match.end() :]


def _clean(value: object) -> str:
    return " ".join(str(value).split()) if value is not None else ""


def skill_purpose(skill_md: str) -> str:
    """The skill's stated purpose, capped at ``PURPOSE_CAP`` characters.

    The frontmatter ``name: description`` when a description exists; else the first ``#``
    heading plus its first paragraph; else the frontmatter name or the first paragraph.
    """
    meta, body = _frontmatter(skill_md)
    name, description = _clean(meta.get("name")), _clean(meta.get("description"))
    if description:
        return (f"{name}: {description}" if name else description)[:PURPOSE_CAP]

    lines = body.split("\n")
    heading_idx = next((i for i, ln in enumerate(lines) if re.match(r"#{1,6}\s+\S", ln)), None)
    start = heading_idx + 1 if heading_idx is not None else 0
    paragraph: list[str] = []
    for ln in lines[start:]:
        if ln.strip():
            paragraph.append(ln.strip())
        elif paragraph:
            break
    text = " ".join(paragraph)
    if heading_idx is not None:
        heading = lines[heading_idx].lstrip("#").strip()
        text = f"{heading}: {text}" if text else heading
    return (text or name)[:PURPOSE_CAP]


def skill_md_path(file_cache: dict[str, str]) -> str | None:
    """The root SKILL.md (else root skill.md) path in the cache, or ``None``."""
    return next((p for p in _SKILL_MD_NAMES if p in file_cache), None)


class NecessityAnalyzer(LLMAnalyzerBase):
    """SKILL.md-only analyzer; the purpose header rides on every chunk's prompt."""

    purpose: str = ""

    def build_prompt(self, batch: Batch, **kwargs: object) -> str:
        header = f"Skill purpose: {self.purpose or '(not stated)'}"
        return BASE_ANALYSIS_PROMPT.format(
            analyzer_prompt=f"{header}\n\n{self.base_prompt}",
            file_label=batch.file_label,
            numbered_content=number_lines(batch.content, batch.start_line),
        )

    def parse_response(self, response: object, batch: Batch) -> list[Finding]:
        """Force EXA-NE1, clamp severity to HIGH/MEDIUM, never set a category."""
        if not isinstance(response, LLMAnalysisResult):
            raise NotImplementedError("NecessityAnalyzer expects LLMAnalysisResult")
        return [
            dataclasses.replace(
                item.to_finding(batch.file_path),
                rule_id=RULE_ID,
                severity=_SEVERITY_CLAMP.get(item.severity, item.severity),
                category=None,
            )
            for item in response.findings
        ]


def _status_only(status: str, reason: LedgerReason) -> AnalyzerNodeResponse:
    return {
        "findings": [],
        "inspection_ledger": [],
        "analyzer_status_events": [
            analyzer_status_event(analyzer_id=ANALYZER_ID, status=status, reason=reason)
        ],
    }


def _failed(batches: list[Batch], exc: Exception) -> tuple[list, dict]:
    outcome = BatchExecutionResult(
        failures=[BatchFailure(batch=b, error_class=type(exc).__name__) for b in batches]
    )
    events, _ = ledger_events_for_batches(ANALYZER_ID, outcome)
    status = analyzer_status_event(
        analyzer_id=ANALYZER_ID,
        status="failed",
        planned_work=[
            {
                "work_id": e["work_id"],
                "path": e["path"],
                "start_line": e["start_line"],
                "end_line": e["end_line"],
            }
            for e in events
        ],
    )
    return events, status


def _model(state: SkillspectorState) -> str:
    model_config: dict[str, str] = state.get("model_config") or {}
    return (
        os.environ.get(MODEL_ENV_VAR, "").strip()
        or model_config.get(ANALYZER_ID)
        or model_config.get("default")
        or _SKILLSPECTOR_DEFAULT_MODEL
    )


def node(state: SkillspectorState) -> AnalyzerNodeResponse:
    """Flag EXA-NE1: SKILL.md steps or rules the skill's stated purpose does not require."""
    if not state.get("use_llm", True):
        logger.info("%s: skipped (use_llm=False)", ANALYZER_ID)
        return _status_only("disabled", LedgerReason.DISABLED_BY_CONFIGURATION)

    file_cache: dict[str, str] = state.get("file_cache") or {}
    skill_path = skill_md_path(file_cache)
    if skill_path is None:
        return _status_only("not_applicable", LedgerReason.NO_APPLICABLE_FILES)

    batches: list[Batch] = []
    analyzer: NecessityAnalyzer | None = None
    try:
        analyzer = NecessityAnalyzer(
            base_prompt=NECESSITY_PROMPT, model=_model(state), node=ANALYZER_ID
        )
        analyzer.purpose = skill_purpose(file_cache[skill_path])
        batches = analyzer.get_batches([skill_path], file_cache)
        results = analyzer.run_batches(batches)
        outcome = getattr(analyzer, "_last_batch_outcome", BatchExecutionResult(successful=results))
        findings = analyzer.collect_findings(outcome.successful)
        events, status = ledger_events_for_batches(ANALYZER_ID, outcome)
        logger.info("%s: %d findings", ANALYZER_ID, len(findings))
        return {
            "findings": findings,
            "inspection_ledger": events,
            "analyzer_status_events": [status],
            "llm_call_log": [
                llm_call_record(ANALYZER_ID, ok=bool(outcome.successful) or not outcome.failures)
            ],
            "inference_usage": analyzer.inference_usage,
        }
    except ValidationError as exc:
        logger.warning("%s: LLM returned malformed response: %s", ANALYZER_ID, exc)
        events, status = _failed(batches, exc)
        return {
            "findings": [],
            "inspection_ledger": events,
            "analyzer_status_events": [status],
            "llm_call_log": [
                llm_call_record(ANALYZER_ID, ok=False, error=f"malformed LLM response: {exc}")
            ],
            "inference_usage": analyzer.inference_usage if analyzer is not None else [],
        }
    except Exception as exc:
        post_response_value_error = (
            isinstance(exc, ValueError) and analyzer is not None and analyzer.response_received
        )
        if isinstance(exc, ValueError) and not post_response_value_error:
            raise
        logger.warning("%s failed: %s", ANALYZER_ID, exc)
        if post_response_value_error:
            events, status = _failed(batches, exc)
        else:
            events, status = (
                [],
                analyzer_status_event(analyzer_id=ANALYZER_ID, status="unavailable"),
            )
        return {
            "findings": [],
            "inspection_ledger": events,
            "analyzer_status_events": [status],
            "llm_call_log": [llm_call_record(ANALYZER_ID, ok=False, error=str(exc))],
            "inference_usage": analyzer.inference_usage if analyzer is not None else [],
        }


def apply() -> None:
    """Register the necessity analyzer node (idempotent)."""
    _analyzer_registry.register_analyzer(ANALYZER_ID, node, enabled=_enabled)


__all__ = ["ANALYZER_ID", "NECESSITY_PROMPT", "NecessityAnalyzer", "apply", "node", "skill_purpose"]
