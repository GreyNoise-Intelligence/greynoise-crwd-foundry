import gzip
import logging
import os
import sys
from unittest import mock

import pytest
import requests
import responses
from crowdstrike.foundry.function import FDKException

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "fe89fa44c0c8441e8a1d3b60d6063411",
                                "v2.0.3-pre-release", "functions", "greynoise-ti-import-to-ng-siem"))
import main  # noqa: E402

GNQL_URL = "https://api.greynoise.io/v3/files/gnql"
CALLBACK_URL = "https://api.greynoise.io/v3/files/callback"
CSV = b"source.ip,source.ip.greynoise.is.actor\r\n198.51.100.1,\r\n"
LOG = logging.getLogger("test")


class FakeNGSIEM:
    def __init__(self, status_code=200):
        self.status_code = status_code
        self.uploads = []

    def upload_file(self, lookup_file, repository):
        with open(lookup_file, "rb") as f:
            self.uploads.append((os.path.basename(lookup_file), repository, f.read()))
        body = {"errors": [{"message": "upload rejected"}]} if self.status_code >= 300 else {"errors": []}
        return {"status_code": self.status_code, "body": body}


@pytest.fixture(autouse=True)
def etag_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "ETAG_DIR", str(tmp_path / "etags"))
    return tmp_path / "etags"


def ok_headers(etag='"v1"', rows="1", truncated="false"):
    return {"ETag": etag, "X-GreyNoise-Generated-At": "2026-10-29T15:00:00Z",
            "X-GreyNoise-Row-Count": rows, "X-GreyNoise-Truncated": truncated}


@pytest.mark.parametrize("name, status, kwargs, feed_status, uploaded", [
    ("200 overwrites the lookup", 200, {"body": CSV, "headers": ok_headers()}, "updated", True),
    ("304 records unchanged", 304, {"headers": {"ETag": '"v1"'}}, "unchanged", False),
    ("202 records provisioning", 202, {"json": {"status": "provisioning"}, "headers": {"Retry-After": "60"}},
     "provisioning", False),
])
@responses.activate
def test_gnql_success_paths(name, status, kwargs, feed_status, uploaded):
    responses.get(GNQL_URL, status=status, **kwargs)
    ngsiem = FakeNGSIEM()

    results = main.import_feeds({"api_key": "k"}, ngsiem, LOG)

    assert [r["feed_status"] for r in results] == [feed_status]
    assert results[0]["status"] == "success"
    assert results[0]["file"] == "ti_greynoise_indicators.csv"
    assert bool(ngsiem.uploads) == uploaded


@pytest.mark.parametrize("name, status, body, code, message", [
    ("401 surfaces the API message", 401, {"error": "invalid API key"}, 401, "invalid API key"),
    ("403 surfaces the API message", 403, {"error": "GNQL feed files are not included in this workspace's plan"},
     403, "not included"),
    ("429 surfaces the API message", 429, {"error": "this GNQL feed is fetched too often; retry later"},
     429, "fetched too often"),
    ("503 surfaces the API message", 503, {"error": "retry later"}, 503, "retry later"),
    ("unexpected 2xx fails as a bad gateway", 204, None, 502, "returned 204"),
])
@responses.activate
def test_gnql_failure_raises(name, status, body, code, message):
    responses.get(GNQL_URL, status=status, json=body)
    ngsiem = FakeNGSIEM()

    with pytest.raises(FDKException) as exc:
        main.import_feeds({"api_key": "k"}, ngsiem, LOG)

    assert exc.value.code == code
    assert message in exc.value.message
    assert ngsiem.uploads == []


@responses.activate
def test_200_uploads_body_and_reports_freshness(etag_dir):
    responses.get(GNQL_URL, body=CSV, headers=ok_headers(rows="1", truncated="true"))
    ngsiem = FakeNGSIEM()

    [result] = main.import_feeds({"api_key": "k", "repository": "my-repo"}, ngsiem, LOG)

    assert ngsiem.uploads == [("ti_greynoise_indicators.csv", "my-repo", CSV)]
    assert result["generated_at"] == "2026-10-29T15:00:00Z"
    assert result["row_count"] == 1
    assert result["truncated"] is True
    assert [p.read_text() for p in etag_dir.iterdir()] == ['"v1"']


@responses.activate
def test_200_deletes_the_temp_file(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(main.tempfile, "mkdtemp", lambda: str(work))
    responses.get(GNQL_URL, body=CSV, headers=ok_headers())

    main.import_feeds({"api_key": "k"}, FakeNGSIEM(), LOG)

    assert not work.exists()


@responses.activate
def test_gzip_body_is_decoded_before_upload():
    responses.get(CALLBACK_URL, body=gzip.compress(CSV), headers={**ok_headers(), "Content-Encoding": "gzip"})
    responses.get(GNQL_URL, status=304)
    ngsiem = FakeNGSIEM()

    main.import_feeds({"api_key": "k", "include_callback_feed": True}, ngsiem, LOG)

    assert ngsiem.uploads == [("ti_greynoise_callback_indicators.csv", "search-all", CSV)]


@responses.activate
def test_failed_upload_raises_and_keeps_the_old_etag(etag_dir):
    responses.get(GNQL_URL, body=CSV, headers=ok_headers())

    with pytest.raises(FDKException) as exc:
        main.import_feeds({"api_key": "k"}, FakeNGSIEM(status_code=500), LOG)

    assert exc.value.code == 502
    assert "upload rejected" in exc.value.message
    assert not etag_dir.exists()


@responses.activate
def test_interrupted_download_raises():
    responses.get(GNQL_URL, body=requests.exceptions.ChunkedEncodingError("connection broken"))

    with pytest.raises(FDKException) as exc:
        main.import_feeds({"api_key": "k"}, FakeNGSIEM(), LOG)

    assert exc.value.code == 502
    assert "connection broken" in exc.value.message


@responses.activate
def test_saved_etag_is_sent_and_304_skips_upload():
    responses.get(GNQL_URL, body=CSV, headers=ok_headers(etag='"v1"'))
    responses.get(GNQL_URL, status=304, headers={"ETag": '"v1"'})
    ngsiem = FakeNGSIEM()

    main.import_feeds({"api_key": "k"}, ngsiem, LOG)
    [result] = main.import_feeds({"api_key": "k"}, ngsiem, LOG)

    assert "If-None-Match" not in responses.calls[0].request.headers
    assert responses.calls[1].request.headers["If-None-Match"] == '"v1"'
    assert result["feed_status"] == "unchanged"
    assert len(ngsiem.uploads) == 1


@responses.activate
def test_changed_query_does_not_reuse_the_etag():
    responses.get(GNQL_URL, body=CSV, headers=ok_headers(etag='"v1"'))

    main.import_feeds({"api_key": "k", "query": "a"}, FakeNGSIEM(), LOG)
    main.import_feeds({"api_key": "k", "query": "b"}, FakeNGSIEM(), LOG)

    assert "If-None-Match" not in responses.calls[1].request.headers


@pytest.mark.parametrize("name, body, want_params", [
    ("defaults", {"api_key": " k "},
     {"query": "last_seen:1d -classification:unknown", "format": "csv", "profile": "ngsiem"}),
    ("tenant limit is sent", {"api_key": "k", "query": "tags:foo", "max_indicator_count": "100000"},
     {"query": "tags:foo", "format": "csv", "profile": "ngsiem", "limit": "100000"}),
    ("invalid limit is dropped", {"api_key": "k", "max_indicator_count": "lots"},
     {"query": "last_seen:1d -classification:unknown", "format": "csv", "profile": "ngsiem"}),
])
@responses.activate
def test_gnql_request(name, body, want_params):
    responses.get(GNQL_URL, status=304)

    main.import_feeds(body, FakeNGSIEM(), LOG)

    request = responses.calls[0].request
    assert request.params == want_params
    assert request.headers["key"] == "k"
    assert request.headers["X-GreyNoise-Integration"] == f"crowdstrike-ngsiem/{main.VERSION}"


@pytest.mark.parametrize("name, include, want_urls", [
    ("callback off by default", None, [GNQL_URL]),
    ("callback on", True, [GNQL_URL, CALLBACK_URL]),
    ("callback on as a string", "true", [GNQL_URL, CALLBACK_URL]),
    ("callback off", False, [GNQL_URL]),
])
@responses.activate
def test_callback_feed_toggle(name, include, want_urls):
    responses.get(GNQL_URL, status=304)
    responses.get(CALLBACK_URL, status=304)

    main.import_feeds({"api_key": "k", "include_callback_feed": include}, FakeNGSIEM(), LOG)

    assert [c.request.url.split("?")[0] for c in responses.calls] == want_urls
    if CALLBACK_URL in want_urls:
        assert responses.calls[1].request.params == {"days": "7", "format": "csv", "profile": "ngsiem"}


@responses.activate
def test_one_failing_feed_does_not_block_the_other():
    responses.get(GNQL_URL, status=400, json={"error": "query is invalid"})
    responses.get(CALLBACK_URL, body=CSV, headers=ok_headers())
    ngsiem = FakeNGSIEM()

    with pytest.raises(FDKException) as exc:
        main.import_feeds({"api_key": "k", "include_callback_feed": True}, ngsiem, LOG)

    assert exc.value.code == 400
    assert "query is invalid" in exc.value.message
    assert [u[0] for u in ngsiem.uploads] == ["ti_greynoise_callback_indicators.csv"]


@responses.activate
def test_changed_repository_does_not_reuse_the_etag():
    responses.get(GNQL_URL, body=CSV, headers=ok_headers(etag='"v1"'))

    main.import_feeds({"api_key": "k", "repository": "a"}, FakeNGSIEM(), LOG)
    main.import_feeds({"api_key": "k", "repository": "b"}, FakeNGSIEM(), LOG)

    assert "If-None-Match" not in responses.calls[1].request.headers


@responses.activate
def test_unexpected_error_raises_with_message_and_other_feed_still_runs():
    responses.get(GNQL_URL, body=CSV, headers=ok_headers())
    responses.get(CALLBACK_URL, body=CSV, headers=ok_headers())
    ngsiem = FakeNGSIEM()
    calls = []

    def upload_file(lookup_file, repository):
        calls.append(os.path.basename(lookup_file))
        if len(calls) == 1:
            raise OSError("disk full")
        return {"status_code": 200, "body": {}}

    ngsiem.upload_file = upload_file

    with pytest.raises(FDKException) as exc:
        main.import_feeds({"api_key": "k", "include_callback_feed": True}, ngsiem, LOG)

    assert exc.value.code == 500
    assert "disk full" in exc.value.message
    assert calls == ["ti_greynoise_indicators.csv", "ti_greynoise_callback_indicators.csv"]


@responses.activate
def test_304_without_row_headers_omits_counts():
    responses.get(GNQL_URL, status=304, headers={"ETag": '"v1"'})

    [result] = main.import_feeds({"api_key": "k"}, FakeNGSIEM(), LOG)

    assert "row_count" not in result
    assert "truncated" not in result


def test_missing_api_key_raises():
    with pytest.raises(FDKException) as exc:
        main.import_feeds({}, FakeNGSIEM(), LOG)
    assert exc.value.code == 400


@responses.activate
def test_handler_returns_results():
    responses.get(GNQL_URL, status=304)
    router = main.func._router
    with mock.patch.object(main, "NGSIEM", FakeNGSIEM):
        resp = router.route(main.Request(method="POST", url="/greynoise-ti-import-bulk", body={"api_key": "k"}), logger=LOG)
    assert resp.code == 200
    assert resp.body["results"][0]["feed_status"] == "unchanged"
