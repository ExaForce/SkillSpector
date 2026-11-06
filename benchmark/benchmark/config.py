"""Provider/run configuration: stable constants and parent-process env wiring."""

from __future__ import annotations

import os

from .auth import token_manager

BEDROCK_BASE_URL_TEMPLATE = "https://bedrock-mantle.{region}.api.aws/v1"
BEDROCK_REGION = "us-east-2"
PROVIDER = "openai"
MODEL_ID = "nvidia.nemotron-super-3-120b"
SCAN_TIMEOUT_SECONDS = 300

# Auto --workers sizing, measured 2026-10-26 on a 48 GB / 16-core Mac: a scan peaks
# ~150 MB RSS (the largest units ~1 GB) and 96 workers use ~5 cores. Above ~96,
# Bedrock starts queueing calls (p99 wait 46s at 128) and throughput drops.
WORKER_RAM_BUDGET_BYTES = 256 * 2**20
WORKERS_PER_CPU = 6
MAX_AUTO_WORKERS = 96

# SkillSpector's own "do not install" verdict == this recommendation string.
MALICIOUS_RECOMMENDATION = "DO_NOT_INSTALL"


def default_workers() -> int:
    """Scan processes this machine can run: the tighter of the RAM and CPU caps."""
    ram = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    by_ram = ram // 2 // WORKER_RAM_BUDGET_BYTES
    by_cpu = (os.cpu_count() or 1) * WORKERS_PER_CPU
    return max(1, min(by_ram, by_cpu, MAX_AUTO_WORKERS))


def bedrock_base_url(region: str) -> str:
    """Bedrock endpoint for ``region`` (keeps the URL in sync with an
    ``AWS_REGION`` override, which also drives the minted token's region).

    An explicit ``BEDROCK_BASE_URL`` env var wins as an escape hatch, for a
    region whose host doesn't follow the ``bedrock-mantle.<region>`` pattern.
    """
    return os.environ.get("BEDROCK_BASE_URL") or BEDROCK_BASE_URL_TEMPLATE.format(region=region)


def configure_run(no_llm: bool, timeout: float) -> tuple[dict, str, str, str]:
    """Set stable env in the parent (inherited by spawned workers) and return
    ``(worker_cfg, provider, model, region)``.

    Stable, non-secret config (provider/model/base-url) is placed in the parent
    ``os.environ`` so every spawned worker inherits it. The volatile bedrock
    token is NOT set here -- each worker mints its own (see ``scan_worker``) so
    it can't go stale across a multi-hour run.
    """
    # Inherited by spawned workers (new interpreters read these at startup), so
    # SkillSpector/langchain import-time warnings and logs stay out of the bar.
    os.environ.setdefault("PYTHONWARNINGS", "ignore")
    os.environ.setdefault("SKILLSPECTOR_LOG_LEVEL", "ERROR")
    cfg = {"use_llm": not no_llm, "mint_bedrock": False, "region": "", "timeout": timeout}
    if no_llm:
        return cfg, "", "", ""
    if os.environ.get("SKILLSPECTOR_PROVIDER"):
        # Caller already configured a provider; trust their env (inherited).
        cfg["region"] = os.environ.get("AWS_REGION", "")
        return (
            cfg,
            os.environ["SKILLSPECTOR_PROVIDER"],
            os.environ.get("SKILLSPECTOR_MODEL", ""),
            cfg["region"],
        )
    # Default path: OpenAI-compatible Bedrock endpoint with a minted token.
    model = os.environ.get("MODEL_OVERRIDE") or os.environ.get("AGENTGUARD_MODEL_ID", MODEL_ID)
    region = os.environ.get("AWS_REGION") or BEDROCK_REGION
    manager = token_manager(region)
    manager.clear_abort()  # drop any stale abort marker from a previous run
    try:
        manager.token()  # fail fast (wait=False) + warm the shared cache
    except Exception as e:  # noqa: BLE001 - surface a clear, actionable hint
        raise SystemExit(
            f"Failed to mint a Bedrock token ({type(e).__name__}: {e}).\n"
            "Refresh AWS credentials (e.g. `aws sso login`), set an existing "
            "SKILLSPECTOR_PROVIDER + key in the env, or pass --no-llm."
        ) from e
    os.environ["SKILLSPECTOR_PROVIDER"] = PROVIDER
    os.environ["SKILLSPECTOR_MODEL"] = model
    os.environ["OPENAI_BASE_URL"] = bedrock_base_url(region)
    cfg.update(mint_bedrock=True, region=region)
    return cfg, PROVIDER, model, region
