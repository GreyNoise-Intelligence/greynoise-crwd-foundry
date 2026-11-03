import os
import shutil
import tempfile
import time
from functools import partial
from typing import Dict

from crowdstrike.foundry.function import FDKException, Function, Request, Response
from falconpy import NGSIEM
from greynoise.api import APIConfig, FileResult, GreyNoise
from greynoise.exceptions import RequestFailure

func = Function.instance()

VERSION = "3.1.0"
INTEGRATION = f"crowdstrike-ngsiem/{VERSION}"
INTEGRATION_NAME = f"CrowdStrike Foundry v{VERSION}"
DEFAULT_QUERY = "last_seen:1d -classification:unknown"
GNQL_FILE = "ti_greynoise_indicators.csv"
CALLBACK_FILE = "ti_greynoise_callback_indicators.csv"
TIMEOUT = (10, 300)
# Leaves room inside the function's 900 s limit to download and upload once the
# feed is built.
PROVISION_TIMEOUT = 600
DEFAULT_RETRY_AFTER = 60


def import_feeds(body: Dict[str, object], ngsiem, logger) -> list:
    api_key = str(body.get("api_key") or "").strip()
    if not api_key:
        raise FDKException(400, "api_key is required")
    repository = str(body.get("repository") or "search-all").strip()
    query = str(body.get("query") or DEFAULT_QUERY).strip()
    limit = str(body.get("max_indicator_count") or "").strip()
    limit = int(limit) if limit.isdigit() and int(limit) > 0 else None

    gn = GreyNoise(APIConfig(api_key=api_key, integration_name=INTEGRATION_NAME, timeout=TIMEOUT))
    feeds = [(GNQL_FILE, partial(gn.gnql_file_metadata, query, limit=limit), partial(gn.gnql_file, query, limit=limit))]
    if str(body.get("include_callback_feed")).lower() == "true":
        feeds.append((CALLBACK_FILE, gn.callback_file_metadata, gn.callback_file))

    deadline = time.monotonic() + PROVISION_TIMEOUT
    results, failures = [], []
    for filename, metadata, download in feeds:
        try:
            results.append(fetch_feed(filename, metadata, download, repository, ngsiem, deadline, logger))
        except FDKException as e:
            logger.error(e.message)
            failures.append(e)
        except Exception as e:
            logger.error(f"{filename}: {e}", exc_info=True)
            failures.append(FDKException(500, f"{filename}: {e}"))
    if failures:
        raise FDKException(max(e.code for e in failures), "; ".join(e.message for e in failures))
    return results


def fetch_feed(filename, metadata, download, repository, ngsiem, deadline, logger) -> dict:
    work_dir = tempfile.mkdtemp()
    try:
        wait_until_built(filename, metadata, deadline, logger)
        path = os.path.join(work_dir, filename)
        result = download(path, integration=INTEGRATION)
        if result.status != FileResult.STATUS_OK:
            raise FDKException(502, f"{filename}: GreyNoise returned {result.status} after reporting the feed built")

        upload = ngsiem.upload_file(lookup_file=path, repository=repository)
        if not 200 <= upload["status_code"] < 300:
            errors = upload.get("body", {}).get("errors") or [{}]
            raise FDKException(502, f"{filename}: NGSIEM upload returned {upload['status_code']}: "
                                    f"{errors[0].get('message', 'unknown error')}")

        message = f"Imported into {repository} ({freshness(result)})"
        logger.info(f"{filename}: {message}")
        return {"file": filename, "status": "success", "message": message}
    except RequestFailure as e:
        status, body = (e.args + (0, None))[:2]
        detail = (body.get("error") or body.get("message") if isinstance(body, dict) else body) or "request failed"
        raise FDKException(status if isinstance(status, int) and 400 <= status < 600 else 502,
                           f"{filename}: GreyNoise API returned {status}: {detail}") from e
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def wait_until_built(filename, metadata, deadline, logger) -> None:
    while True:
        built = metadata(integration=INTEGRATION)
        if built.status == FileResult.STATUS_OK:
            return
        wait = max(built.retry_after or DEFAULT_RETRY_AFTER, 1)
        if time.monotonic() + wait > deadline:
            raise FDKException(504, f"{filename}: GreyNoise is still building the feed after {PROVISION_TIMEOUT} s")
        logger.info(f"{filename}: GreyNoise is building the feed; checking again in {wait} s")
        time.sleep(wait)


def freshness(result: FileResult) -> str:
    parts = [f"generated at {result.generated_at or 'unknown'}"]
    if result.row_count is not None:
        parts.append(f"{result.row_count} rows")
    if result.truncated:
        parts.append("truncated")
    return ", ".join(parts)


@func.handler(method="POST", path="/greynoise-ti-import-bulk")
def on_post(request: Request, config: Dict[str, object] | None, logger) -> Response:
    return Response(body={"results": import_feeds(request.body, NGSIEM(), logger)}, code=200)


if __name__ == "__main__":
    func.run()
