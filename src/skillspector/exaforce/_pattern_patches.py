# SPDX-License-Identifier: Apache-2.0
"""Anchor two static patterns that match inside unrelated words (fork behavior).

Both corrections are one regex boundary, and both were the *highest-scoring
verdicts in a production fleet scan* -- not hypotheticals. Measured over 111
shipped findings (111 rows, 100 unique skill content hashes, 50 repos, scanned
2026-09-11), re-adjudicated against the evidence each row carries:

  rank 1   P5  "harmful content"     100 / CRITICAL / DO_NOT_INSTALL
  rank 2   PE3 "credential access"   100 / CRITICAL / DO_NOT_INSTALL

Neither row contains a security defect.

**P5** emits at CRITICAL with confidence 0.95, which is 47 of the 50 available
CRITICAL points before any other rule contributes. Its pattern has no word
boundary, so ``kill`` matches inside ``skill``:

    "... not a separate optional skill someone might remember to run."
                                  ^^^^^^^^^^^^^^

The highest verdict in the fleet was the substring ``kill`` inside the word
``skill`` -- in a scanner whose entire input domain is skills.

**PE3** matches ``.env`` with nothing to its left, so it fires on ``process.env``
in a front-end style guide -- twice, including on the line that reads "Access
environment variables **safely**" and on the CSV's *anti*-pattern column. There
is no credential access anywhere in the 1,965 characters of cited evidence.

Why here and not upstream-in-place: these are domain corrections the fork needs
now, and ``replace_pattern`` fails loudly if upstream rewrites either pattern or
fixes it first, so a merge cannot leave a stale correction applied or shadow an
upstream fix. The boundary-anchoring is domain-neutral and worth offering
upstream; this module is the interim.

Full analysis: ``tools/agentguard/docs/plans/0003-skillspector-risk-scoring-review.md``
in ExaForce/operations (sections 3 and "What it costs today").
"""

from __future__ import annotations

import skillspector.nodes.analyzers.static_patterns_harmful_content as harmful
import skillspector.nodes.analyzers.static_patterns_privilege_escalation as privesc

from ._patchlib import replace_pattern

# `\b` before the verb alternation. `kill` in `skill` has a word character to
# its left, so the boundary fails there and holds for a real "kill someone".
P5_HARM_OLD = r"(?:how\s+to\s+)?(?:poison|kill|murder)\s+(?:someone|a\s+person|people)"
P5_HARM_NEW = r"(?:how\s+to\s+)?\b(?:poison|kill|murder)\s+(?:someone|a\s+person|people)"

# `(?<![\w.])` before the dot. `process.env` has `s` to the left of `.env` and
# is rejected; a bare `.env`, `cat .env`, `~/.env` and `.env.production` all
# still match, because `/`, a space and line start are not word characters.
PE3_ENV_OLD = r"\.env(?:\.local|\.production|\.development)?(?:\s|$|['\"])"
PE3_ENV_NEW = r"(?<![\w.])\.env(?:\.local|\.production|\.development)?(?:\s|$|['\"])"


def apply() -> None:
    """Idempotently anchor the two unbounded patterns."""
    replace_pattern(harmful, "DANGEROUS_ACTIONS", P5_HARM_OLD, P5_HARM_NEW)
    replace_pattern(privesc, "PE3_PATTERNS", PE3_ENV_OLD, PE3_ENV_NEW)
