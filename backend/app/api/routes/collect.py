"""
Live collection API: audit a device by reaching it, instead of uploading its configuration.

The route is a fetch in front of the ordinary scan. It pulls configuration text over SSH
(``app.collect``) and hands it to ``scan.run_scan``, so a collected device and an uploaded file
produce the same scan object, the same redaction and the same AI behaviour. Nothing downstream is
told where the text came from, and nothing needs to be.

Two things are deliberately restrictive:

  * The feature is off unless ``LIVE_COLLECTION_ENABLED`` is set. An endpoint that opens an SSH
    session to an arbitrary host on request is a pivot into the network the backend sits in, so it
    stays closed on a deployment that did not ask for it.
  * Credentials are never persisted. They arrive in the request body, open one session, and go out of
    scope with it. They are not written to the scan store, not archived with the scan, and not logged
    -only the configuration text survives the call, and that is redacted by the scan pipeline exactly
    as an uploaded one is.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from app.api.routes.scan import run_scan, validated_framework
from app.api.schemas import (
    CollectCapabilitiesResponse,
    CollectRequest,
    CollectResponse,
)
from app.collect import CollectionError, Target, available_methods, collect, platform_choices
from app import config as app_config

router = APIRouter()
logger = logging.getLogger(__name__)


def _require_enabled() -> None:
    # read at call time, not bound at import: tests (and a config reload) replace the settings object
    if not app_config.settings.live_collection_enabled:
        raise HTTPException(
            403,
            "Live collection is disabled on this backend. It opens SSH sessions to the devices it is "
            "given, so it is enabled deliberately: set LIVE_COLLECTION_ENABLED=true to turn it on.",
        )


@router.get("/collect/capabilities", response_model=CollectCapabilitiesResponse)
async def collect_capabilities():
    """What this backend can collect, so the form can say so before a credential is typed.

    Always 200: 'collection is off here' and 'Netmiko is not installed' are answers an operator needs,
    not errors.
    """
    return CollectCapabilitiesResponse(
        enabled=app_config.settings.live_collection_enabled,
        methods=list(available_methods()),
        platforms=platform_choices(),
    )


@router.post("/collect", response_model=CollectResponse)
async def collect_and_scan(request: CollectRequest):
    """Pull the running configuration from each device, then audit what was collected.

    Partial success is the normal case on a real network: devices that answered are scanned, and the
    ones that did not are reported per host with the reason. Only when every device fails does this
    return an error, because then there is nothing to audit.
    """
    _require_enabled()
    framework = validated_framework(request.framework)

    targets = [
        Target(
            host=t.host.strip(),
            platform=t.platform,
            username=t.username,
            password=t.password,
            port=t.port,
            enable=t.enable,
            method=t.method,
            timeout=t.timeout,
        )
        for t in request.targets
    ]

    sources: list[tuple[str, str]] = []
    failures: list[dict] = []
    for target in targets:
        try:
            sources.append((target.host, collect(target)))
        except CollectionError as e:
            # str(e) is written for an operator and never quotes a credential; the Target repr is
            # overridden for the same reason, so this log line cannot leak one either
            logger.warning("Collection failed for %r: %s", target, e)
            failures.append({"host": target.host, "error": str(e)})

    if not sources:
        raise HTTPException(
            502,
            {
                "message": "No device could be collected from",
                "errors": {f["host"]: f["error"] for f in failures},
            },
        )

    return CollectResponse(
        scan=run_scan(sources, framework),
        collected=[host for host, _ in sources],
        failures=failures,
    )
