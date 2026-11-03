# SPDX-License-Identifier: Apache-2.0
"""Per-skill instruction-flow analyzer (EXA-IF1), gated by ``SKILLSPECTOR_EXA_INSTRUCTION_FLOW=on``.

Upstream LLM analyzers judge each file alone, so a step that only looks wrong next to
the skill's stated purpose (an innocuous SKILL.md telling the agent to follow a
referenced file that quietly does something else) is missed. This node sends one
bundle per skill to the LLM: root SKILL.md, then the files it references, each after a
``=== FILE: <path> ===`` separator (``_skill_refs.build_bundle``). The model lists every
instructed action, weighs it against the purpose, and reports the unnecessary ones.

The node runs only when the bundle holds at least one referenced file; otherwise it
reports ``not_applicable`` and makes no LLM call. Findings are mapped from bundle lines
back to the real file and line, forced to ``EXA-IF1`` with severity HIGH or MEDIUM, and
never given a ``category`` so the fork's semantic floor treats them as LLM findings.

Model: ``SKILLSPECTOR_MODEL_EXAFORCE_INSTRUCTION_FLOW``, then ``model_config`` for this
node, then ``model_config["default"]``, then the upstream default. Both env vars are read
on every call.
"""

from __future__ import annotations

import dataclasses
import os

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
)
from skillspector.logging_config import get_logger
from skillspector.models import Finding
from skillspector.state import AnalyzerNodeResponse, SkillspectorState, llm_call_record

from . import _analyzer_registry, _skill_refs

ANALYZER_ID = "exaforce_instruction_flow"
RULE_ID = "EXA-IF1"
ENV_VAR = "SKILLSPECTOR_EXA_INSTRUCTION_FLOW"
MODEL_ENV_VAR = "SKILLSPECTOR_MODEL_EXAFORCE_INSTRUCTION_FLOW"

_SEVERITY_CLAMP = {"CRITICAL": "HIGH", "LOW": "MEDIUM"}
_BUNDLE_LABEL = "Skill bundle: SKILL.md and the files it references"

logger = get_logger(__name__)

INSTRUCTION_FLOW_PROMPT = """\
You review one AI agent skill as a whole: its SKILL.md plus the files SKILL.md points \
the agent to. The question is necessity, not presence: does the skill's stated purpose \
require each action it makes the agent take?

Input format: a bundle of several files. Each file starts with a separator line \
"=== FILE: <path> ===". SKILL.md comes first. Line numbers (the L-prefixes) are the \
bundle's own numbering across all files, not per-file numbering.

Steps:
1. Stated purpose: the frontmatter name and description, and what the SKILL.md body \
says the skill is for.
2. List to yourself every action the bundle instructs the agent to take, in any file: \
commands or scripts to run (including what those scripts do), files to read, write or \
delete, settings or permissions to change, data to send, fetch or store, edits to the \
content or numbers of the output, and anything to keep from the user.
3. For each action, decide whether the stated purpose requires it. Report only the \
actions it does not require.

Judge setup, preflight and baseline steps like any other action. A step that hides, \
filters, ignores or rewrites what the skill reports or produces (for example adding \
entries to an ignore list or allowlist, or adjusting numbers) changes the output, even \
when it is described as configuration. Fetching code from outside the skill and \
running it (for example piping a downloaded script to a shell) is also an action: the \
purpose must require that particular remote code.

Not findings:
- referencing, reading or following another file of the skill ("read REFERENCE.md \
first" is normal);
- any action the purpose needs, however powerful it sounds;
- weaknesses in how the skill's code or configuration is written (a hardcoded key, a \
default password, a service running as root, an insecure flag, missing validation): \
report actions the agent is told to take, not code quality;
- what a bundled script could do when no file tells the agent to run it;
- an optional step the user chooses that fits the stated purpose.
A sensitive-looking step the purpose calls for is fine; a harmless-looking step the \
purpose does not call for is a finding.

Report each unnecessary action as rule_id EXA-IF1, with start_line on the bundle line \
where that action is instructed (end_line, if given, in the same file). The message \
names the action and why the purpose does not need it, in one sentence. Confidence is \
how sure you are that the purpose does not require the action.

Severity:
- HIGH only when all three hold: (a) the action touches host configuration, \
credentials, keys, the network, logs or permissions, or changes facts or numbers in the \
output; (b) the stated purpose does not require it; (c) it is presented as mandatory, \
or as something not to mention to the user.
- MEDIUM for every other unnecessary action (unnecessary but benign-looking).
Never use LOW or CRITICAL.

Output only the findings, not the list of actions. If every action is needed, return \
no findings.
"""


def _enabled() -> bool:
    return os.environ.get(ENV_VAR, "").strip().lower() == "on"


def instruction_bundle(file_cache: dict[str, str]) -> _skill_refs.Bundle | None:
    """The skill's bundle, or ``None`` without root SKILL.md or any bundled referenced file."""
    skill_path = next((p for p in _skill_refs._SKILL_MD_NAMES if p in file_cache), None)
    if skill_path is None:
        return None
    refs = _skill_refs.referenced_files(file_cache[skill_path], sorted(file_cache))
    if not refs:
        return None
    bundle = _skill_refs.build_bundle(skill_path, file_cache, refs)
    return bundle if len(bundle.offsets) > 1 else None


def _number_bundle_lines(text: str) -> str:
    # Number by "\n" only, as map_line does; str.splitlines() would also split on
    # \x0c, \u2028 and the like and shift every later line number.
    lines = text.split("\n")
    width = len(str(len(lines)))
    return "\n".join(f"L{i:0>{width}}: {line}" for i, line in enumerate(lines, 1))


class InstructionFlowAnalyzer(LLMAnalyzerBase):
    """One LLM call per skill over the instruction-flow bundle."""

    _bundle: _skill_refs.Bundle | None = None

    def get_batches(
        self,
        file_paths: list[str],
        file_cache: dict[str, str],
        findings: list[Finding] | None = None,
    ) -> list[Batch]:
        """Exactly one batch holding the bundle, labelled with root SKILL.md; none if N/A."""
        if self._bundle is None:
            self._bundle = instruction_bundle(file_cache)
        if self._bundle is None:
            return []
        return [Batch(file_path=self._bundle.offsets[0][1], content=self._bundle.text)]

    def build_prompt(self, batch: Batch, **kwargs: object) -> str:
        return BASE_ANALYSIS_PROMPT.format(
            analyzer_prompt=self.base_prompt,
            file_label=_BUNDLE_LABEL,
            numbered_content=_number_bundle_lines(batch.content),
        )

    def _last_line_of_file(self, bundle_line: int) -> int:
        """Last bundle line of the file containing ``bundle_line``."""
        bundle = self._bundle
        assert bundle is not None
        later = [start for start, _, _ in bundle.offsets if start > bundle_line]
        return min(later) - 1 if later else bundle.text.count("\n") + 1

    def parse_response(self, response: object, batch: Batch) -> list[Finding]:
        """Map bundle lines to real files and lines; force EXA-IF1 and clamp severity."""
        if not isinstance(response, LLMAnalysisResult):
            raise NotImplementedError("InstructionFlowAnalyzer expects LLMAnalysisResult")
        bundle = self._bundle
        if bundle is None:
            return []
        files = {path for _, path, _ in bundle.offsets}
        out: list[Finding] = []
        for item in response.findings:
            path, start = _skill_refs.map_line(bundle, item.start_line)
            if path not in files:
                continue
            end = None
            if item.end_line is not None:
                end_bundle = max(item.end_line, item.start_line)
                end_path, end = _skill_refs.map_line(bundle, end_bundle)
                if end_path != path:
                    _, end = _skill_refs.map_line(bundle, self._last_line_of_file(item.start_line))
                end = max(end, start)
            out.append(
                dataclasses.replace(
                    item.to_finding(path),
                    rule_id=RULE_ID,
                    severity=_SEVERITY_CLAMP.get(item.severity, item.severity),
                    start_line=start,
                    end_line=end,
                    category=None,
                )
            )
        return out


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
    """Flag EXA-IF1: actions the skill instructs that its stated purpose does not require."""
    if not state.get("use_llm", True):
        logger.info("%s: skipped (use_llm=False)", ANALYZER_ID)
        return _status_only("disabled", LedgerReason.DISABLED_BY_CONFIGURATION)

    file_cache: dict[str, str] = state.get("file_cache") or {}
    bundle = instruction_bundle(file_cache)
    if bundle is None:
        return _status_only("not_applicable", LedgerReason.NO_APPLICABLE_FILES)

    batches: list[Batch] = []
    analyzer: InstructionFlowAnalyzer | None = None
    try:
        analyzer = InstructionFlowAnalyzer(
            base_prompt=INSTRUCTION_FLOW_PROMPT, model=_model(state), node=ANALYZER_ID
        )
        analyzer._bundle = bundle
        batches = analyzer.get_batches(sorted(file_cache), file_cache)
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
    """Register the instruction-flow analyzer node (idempotent)."""
    _analyzer_registry.register_analyzer(ANALYZER_ID, node, enabled=_enabled)


__all__ = ["ANALYZER_ID", "INSTRUCTION_FLOW_PROMPT", "InstructionFlowAnalyzer", "apply", "node"]
