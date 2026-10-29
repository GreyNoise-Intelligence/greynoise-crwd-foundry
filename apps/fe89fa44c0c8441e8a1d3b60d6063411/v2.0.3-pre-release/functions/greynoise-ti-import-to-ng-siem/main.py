import hashlib
import json
import os
import shutil
import tempfile
from typing import Dict

import requests
from crowdstrike.foundry.function import FDKException, Function, Request, Response
from falconpy import NGSIEM

func = Function.instance()

VERSION = "3.1.0"
API_URL = "https://api.greynoise.io/v3/files"
DEFAULT_QUERY = "last_seen:1d -classification:unknown"
GNQL_FILE = "ti_greynoise_indicators.csv"
CALLBACK_FILE = "ti_greynoise_callback_indicators.csv"
# /tmp outlives a warm invocation but not a cold start; losing an ETag costs one
# full download, never a missed update. No collection, so the auth scopes stay
# as published and this ships as a minor version.
ETAG_DIR = os.path.join(tempfile.gettempdir(), "greynoise-etags")
TIMEOUT = (10, 300)
CHUNK_SIZE = 1 << 20


def import_feeds(body: Dict[str, object], ngsiem, logger) -> list:
    api_key = str(body.get("api_key") or "").strip()
    if not api_key:
        raise FDKException(400, "api_key is required")
    repository = str(body.get("repository") or "search-all").strip()
    gnql_params = {
        "query": str(body.get("query") or DEFAULT_QUERY).strip(),
        "format": "csv",
        "profile": "ngsiem",
    }
    limit = str(body.get("max_indicator_count") or "").strip()
    if limit.isdigit() and int(limit) > 0:
        gnql_params["limit"] = limit

    feeds = [("gnql", gnql_params, GNQL_FILE)]
    if str(body.get("include_callback_feed")).lower() == "true":
        feeds.append(("callback", {"days": "7", "format": "csv", "profile": "ngsiem"}, CALLBACK_FILE))

    results, failures = [], []
    for feed, params, filename in feeds:
        try:
            results.append(fetch_feed(feed, params, filename, api_key, repository, ngsiem, logger))
        except FDKException as e:
            logger.error(f"{filename}: {e.message}")
            failures.append(e)
        except Exception as e:
            logger.error(f"{filename}: {e}", exc_info=True)
            failures.append(FDKException(500, f"{filename}: {e}"))
    if failures:
        raise FDKException(max(e.code for e in failures), "; ".join(e.message for e in failures))
    return results


def fetch_feed(feed, params, filename, api_key, repository, ngsiem, logger) -> dict:
    cache_key = json.dumps([api_key, repository, feed, params], sort_keys=True).encode()
    etag_path = os.path.join(ETAG_DIR, hashlib.sha256(cache_key).hexdigest())
    headers = {"key": api_key, "X-GreyNoise-Integration": f"crowdstrike-ngsiem/{VERSION}"}
    if os.path.exists(etag_path):
        with open(etag_path, encoding="utf-8") as f:
            headers["If-None-Match"] = f.read()

    work_dir = tempfile.mkdtemp()
    try:
        path = os.path.join(work_dir, filename)
        with requests.get(f"{API_URL}/{feed}", params=params, headers=headers, stream=True, timeout=TIMEOUT) as resp:
            result = {"file": filename, "status": "success",
                      "generated_at": resp.headers.get("X-GreyNoise-Generated-At", "")}
            rows = resp.headers.get("X-GreyNoise-Row-Count", "")
            if rows.isdigit():
                result["row_count"] = int(rows)
            if "X-GreyNoise-Truncated" in resp.headers:
                result["truncated"] = resp.headers["X-GreyNoise-Truncated"].lower() == "true"
            if resp.status_code == 304:
                logger.info(f"{filename}: unchanged")
                return {**result, "feed_status": "unchanged", "message": "Unchanged since the last import"}
            if resp.status_code == 202:
                logger.info(f"{filename}: provisioning")
                return {**result, "feed_status": "provisioning", "message": "Feed is being built; the next run imports it"}
            if resp.status_code != 200:
                raise FDKException(resp.status_code if resp.status_code >= 400 else 502,
                                   f"{filename}: GreyNoise API returned {resp.status_code}: {api_error(resp)}")
            with open(path, "wb") as f:
                for chunk in resp.iter_content(CHUNK_SIZE):
                    f.write(chunk)
            etag = resp.headers.get("ETag", "")

        upload = ngsiem.upload_file(lookup_file=path, repository=repository)
        if not 200 <= upload["status_code"] < 300:
            errors = upload.get("body", {}).get("errors") or [{}]
            raise FDKException(502, f"{filename}: NGSIEM upload returned {upload['status_code']}: "
                                    f"{errors[0].get('message', 'unknown error')}")

        if etag:
            os.makedirs(ETAG_DIR, exist_ok=True)
            with open(etag_path, "w", encoding="utf-8") as f:
                f.write(etag)
        logger.info(f"{filename}: imported {result.get('row_count', 'unknown')} rows into {repository}")
        return {**result, "feed_status": "updated", "message": "File imported"}
    except requests.RequestException as e:
        raise FDKException(502, f"{filename}: GreyNoise API request failed: {e}") from e
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def api_error(resp) -> str:
    try:
        body = resp.json()
    except ValueError:
        return resp.reason
    return (body.get("error") or body.get("message") if isinstance(body, dict) else None) or resp.reason


@func.handler(method="POST", path="/greynoise-ti-import-bulk")
def on_post(request: Request, config: Dict[str, object] | None, logger) -> Response:
    return Response(body={"results": import_feeds(request.body, NGSIEM(), logger)}, code=200)


if __name__ == "__main__":
    func.run()
