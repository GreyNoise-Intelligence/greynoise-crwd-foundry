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
GNQL_METADATA_URL = GNQL_URL + "/metadata"
CALLBACK_URL = "https://api.greynoise.io/v3/files/callback"
CALLBACK_METADATA_URL = CALLBACK_URL + "/metadata"
CSV = b"source.ip,source.ip.greynoise.is.actor\r\n198.51.100.1,\r\n"
GENERATED_AT = "2026-10-29T15:00:00Z"
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


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.fixture(autouse=True)
def etag_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "ETAG_DIR", str(tmp_path / "etags"))
    return tmp_path / "etags"


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(main, "time", fake)
    return fake


def feed_headers(etag='"v1"', rows="1", truncated="false"):
    return {"ETag": etag, "X-GreyNoise-Generated-At": GENERATED_AT,
            "X-GreyNoise-Row-Count": rows, "X-GreyNoise-Truncated": truncated}


def built(url=GNQL_METADATA_URL, **headers):
    responses.get(url, json={"status": "enabled"}, headers=feed_headers(**headers))


def building(url=GNQL_METADATA_URL, retry_after="60"):
    responses.get(url, status=202, json={"status": "provisioning"},
                  headers={"Retry-After": retry_after} if retry_after else {})


def calls_to(url):
    return [c for c in responses.calls if c.request.url.split("?")[0] == url]


@pytest.mark.parametrize("name, status, kwargs, message, uploaded", [
    ("200 overwrites the lookup", 200, {"body": CSV, "headers": feed_headers()},
     f"Imported into search-all (generated at {GENERATED_AT}, 1 rows)", True),
    ("304 records unchanged with the metadata's freshness", 304, {"headers": {"ETag": '"v1"'}},
     f"Unchanged since the last import (generated at {GENERATED_AT}, 1 rows)", False),
])
@responses.activate
def test_gnql_success_paths(name, status, kwargs, message, uploaded):
    built()
    responses.get(GNQL_URL, status=status, **kwargs)
    ngsiem = FakeNGSIEM()

    results = main.import_feeds({"api_key": "k"}, ngsiem, LOG)

    assert results == [{"file": "ti_greynoise_indicators.csv", "status": "success", "message": message}]
    assert bool(ngsiem.uploads) == uploaded


@pytest.mark.parametrize("name, retry_after, want_sleeps", [
    ("honours Retry-After", "30", [30, 30]),
    ("defaults without Retry-After", None, [60, 60]),
    ("defaults on an unparseable Retry-After", "soon", [60, 60]),
])
@responses.activate
def test_waits_on_metadata_until_built_then_downloads_once(name, retry_after, want_sleeps, clock):
    building(retry_after=retry_after)
    building(retry_after=retry_after)
    built()
    responses.get(GNQL_URL, body=CSV, headers=feed_headers())
    ngsiem = FakeNGSIEM()

    [result] = main.import_feeds({"api_key": "k"}, ngsiem, LOG)

    assert clock.sleeps == want_sleeps
    assert len(calls_to(GNQL_METADATA_URL)) == 3
    assert len(calls_to(GNQL_URL)) == 1
    assert result["message"].startswith("Imported")
    assert ngsiem.uploads == [("ti_greynoise_indicators.csv", "search-all", CSV)]


@responses.activate
def test_still_building_at_the_deadline_raises_without_downloading(clock):
    building()
    ngsiem = FakeNGSIEM()

    with pytest.raises(FDKException) as exc:
        main.import_feeds({"api_key": "k"}, ngsiem, LOG)

    assert exc.value.code == 504
    assert "still building" in exc.value.message
    assert sum(clock.sleeps) <= main.PROVISION_TIMEOUT
    assert calls_to(GNQL_URL) == []
    assert ngsiem.uploads == []


@responses.activate
def test_provisioning_deadline_is_shared_across_feeds(clock):
    building(retry_after="300")
    building(retry_after="300")
    built()
    responses.get(GNQL_URL, body=CSV, headers=feed_headers())
    building(CALLBACK_METADATA_URL)

    with pytest.raises(FDKException) as exc:
        main.import_feeds({"api_key": "k", "include_callback_feed": True}, FakeNGSIEM(), LOG)

    assert exc.value.code == 504
    assert "ti_greynoise_callback_indicators.csv" in exc.value.message
    assert clock.sleeps == [300, 300]


@responses.activate
def test_download_provisioning_after_metadata_reported_built_raises():
    built()
    building(GNQL_URL)

    with pytest.raises(FDKException) as exc:
        main.import_feeds({"api_key": "k"}, FakeNGSIEM(), LOG)

    assert exc.value.code == 502
    assert "provisioning" in exc.value.message


@pytest.mark.parametrize("name, url, status, body, code, message", [
    ("metadata 401 surfaces the API message", GNQL_METADATA_URL, 401, {"error": "invalid API key"},
     401, "invalid API key"),
    ("metadata 403 surfaces the API message", GNQL_METADATA_URL, 403,
     {"error": "GNQL feed files are not included in this workspace's plan"}, 403, "not included"),
    ("metadata 429 surfaces the API message", GNQL_METADATA_URL, 429,
     {"error": "this GNQL feed is fetched too often; retry later"}, 429, "fetched too often"),
    ("metadata 400 surfaces the query error", GNQL_METADATA_URL, 400, {"error": "query is invalid"},
     400, "query is invalid"),
    ("download 503 surfaces the API message", GNQL_URL, 503, {"error": "retry later"}, 503, "retry later"),
    ("download 500 surfaces the API message", GNQL_URL, 500, {"error": "failed to read GNQL feed file"},
     500, "failed to read"),
])
@responses.activate
def test_error_responses_raise(name, url, status, body, code, message):
    if url == GNQL_URL:
        built()
    responses.get(url, status=status, json=body)
    ngsiem = FakeNGSIEM()

    with pytest.raises(FDKException) as exc:
        main.import_feeds({"api_key": "k"}, ngsiem, LOG)

    assert exc.value.code == code
    assert message in exc.value.message
    assert ngsiem.uploads == []


@responses.activate
def test_200_uploads_body_and_reports_freshness(etag_dir):
    built(rows="1", truncated="true")
    responses.get(GNQL_URL, body=CSV, headers=feed_headers(rows="1", truncated="true"))
    ngsiem = FakeNGSIEM()

    [result] = main.import_feeds({"api_key": "k", "repository": "my-repo"}, ngsiem, LOG)

    assert ngsiem.uploads == [("ti_greynoise_indicators.csv", "my-repo", CSV)]
    assert result["message"] == f"Imported into my-repo (generated at {GENERATED_AT}, 1 rows, truncated)"
    assert [p.read_text() for p in etag_dir.iterdir()] == ['"v1"']


@responses.activate
def test_200_deletes_the_temp_file(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(main.tempfile, "mkdtemp", lambda: str(work))
    built()
    responses.get(GNQL_URL, body=CSV, headers=feed_headers())

    main.import_feeds({"api_key": "k"}, FakeNGSIEM(), LOG)

    assert not work.exists()


@responses.activate
def test_gzip_body_is_decoded_before_upload():
    built()
    responses.get(GNQL_URL, status=304)
    built(CALLBACK_METADATA_URL)
    responses.get(CALLBACK_URL, body=gzip.compress(CSV), headers={**feed_headers(), "Content-Encoding": "gzip"})
    ngsiem = FakeNGSIEM()

    main.import_feeds({"api_key": "k", "include_callback_feed": True}, ngsiem, LOG)

    assert ngsiem.uploads == [("ti_greynoise_callback_indicators.csv", "search-all", CSV)]


@responses.activate
def test_failed_upload_raises_and_keeps_the_old_etag(etag_dir):
    built()
    responses.get(GNQL_URL, body=CSV, headers=feed_headers())

    with pytest.raises(FDKException) as exc:
        main.import_feeds({"api_key": "k"}, FakeNGSIEM(status_code=500), LOG)

    assert exc.value.code == 502
    assert "upload rejected" in exc.value.message
    assert not etag_dir.exists()


@responses.activate
def test_interrupted_download_raises():
    built()
    responses.get(GNQL_URL, body=requests.exceptions.ChunkedEncodingError("connection broken"))

    with pytest.raises(FDKException) as exc:
        main.import_feeds({"api_key": "k"}, FakeNGSIEM(), LOG)

    assert exc.value.code == 502
    assert "connection broken" in exc.value.message


@responses.activate
def test_saved_etag_is_sent_and_304_skips_upload():
    built()
    responses.get(GNQL_URL, body=CSV, headers=feed_headers(etag='"v1"'))
    responses.get(GNQL_URL, status=304, headers={"ETag": '"v1"'})
    ngsiem = FakeNGSIEM()

    main.import_feeds({"api_key": "k"}, ngsiem, LOG)
    [result] = main.import_feeds({"api_key": "k"}, ngsiem, LOG)

    first, second = calls_to(GNQL_URL)
    assert "If-None-Match" not in first.request.headers
    assert second.request.headers["If-None-Match"] == '"v1"'
    assert result["message"].startswith("Unchanged")
    assert len(ngsiem.uploads) == 1


@pytest.mark.parametrize("name, first, second", [
    ("changed query", {"query": "a"}, {"query": "b"}),
    ("changed limit", {"max_indicator_count": "10"}, {"max_indicator_count": "20"}),
    ("changed repository", {"repository": "a"}, {"repository": "b"}),
    ("changed api key", {"api_key": "k1"}, {"api_key": "k2"}),
])
@responses.activate
def test_changed_settings_do_not_reuse_the_etag(name, first, second):
    built()
    responses.get(GNQL_URL, body=CSV, headers=feed_headers(etag='"v1"'))

    main.import_feeds({"api_key": "k", **first}, FakeNGSIEM(), LOG)
    main.import_feeds({"api_key": "k", **second}, FakeNGSIEM(), LOG)

    assert "If-None-Match" not in calls_to(GNQL_URL)[1].request.headers


@pytest.mark.parametrize("name, body, want_params", [
    ("defaults", {"api_key": " k "},
     {"query": "last_seen:1d -classification:unknown", "format": "csv", "profile": "ngsiem"}),
    ("tenant limit is sent", {"api_key": "k", "query": "tags:foo", "max_indicator_count": "100000"},
     {"query": "tags:foo", "format": "csv", "profile": "ngsiem", "limit": "100000"}),
    ("invalid limit is dropped", {"api_key": "k", "max_indicator_count": "lots"},
     {"query": "last_seen:1d -classification:unknown", "format": "csv", "profile": "ngsiem"}),
])
@responses.activate
def test_gnql_requests(name, body, want_params):
    built()
    responses.get(GNQL_URL, status=304)

    main.import_feeds(body, FakeNGSIEM(), LOG)

    assert len(responses.calls) == 2
    for call in responses.calls:
        assert call.request.params == want_params
        assert call.request.headers["key"] == "k"
        assert call.request.headers["X-GreyNoise-Integration"] == f"crowdstrike-ngsiem/{main.VERSION}"


@pytest.mark.parametrize("name, include, want_urls", [
    ("callback off by default", None, [GNQL_METADATA_URL, GNQL_URL]),
    ("callback on", True, [GNQL_METADATA_URL, GNQL_URL, CALLBACK_METADATA_URL, CALLBACK_URL]),
    ("callback on as a string", "true", [GNQL_METADATA_URL, GNQL_URL, CALLBACK_METADATA_URL, CALLBACK_URL]),
    ("callback off", False, [GNQL_METADATA_URL, GNQL_URL]),
])
@responses.activate
def test_callback_feed_toggle(name, include, want_urls):
    built()
    responses.get(GNQL_URL, status=304)
    built(CALLBACK_METADATA_URL)
    responses.get(CALLBACK_URL, status=304)

    main.import_feeds({"api_key": "k", "include_callback_feed": include}, FakeNGSIEM(), LOG)

    assert [c.request.url.split("?")[0] for c in responses.calls] == want_urls
    for call in calls_to(CALLBACK_URL):
        assert call.request.params == {"days": "7", "format": "csv", "profile": "ngsiem"}


@responses.activate
def test_one_failing_feed_does_not_block_the_other():
    responses.get(GNQL_METADATA_URL, status=400, json={"error": "query is invalid"})
    built(CALLBACK_METADATA_URL)
    responses.get(CALLBACK_URL, body=CSV, headers=feed_headers())
    ngsiem = FakeNGSIEM()

    with pytest.raises(FDKException) as exc:
        main.import_feeds({"api_key": "k", "include_callback_feed": True}, ngsiem, LOG)

    assert exc.value.code == 400
    assert "query is invalid" in exc.value.message
    assert [u[0] for u in ngsiem.uploads] == ["ti_greynoise_callback_indicators.csv"]


@responses.activate
def test_unexpected_error_raises_with_message_and_other_feed_still_runs():
    built()
    responses.get(GNQL_URL, body=CSV, headers=feed_headers())
    built(CALLBACK_METADATA_URL)
    responses.get(CALLBACK_URL, body=CSV, headers=feed_headers())
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


def test_missing_api_key_raises():
    with pytest.raises(FDKException) as exc:
        main.import_feeds({}, FakeNGSIEM(), LOG)
    assert exc.value.code == 400


@responses.activate
def test_handler_returns_results():
    built()
    responses.get(GNQL_URL, status=304)
    router = main.func._router
    with mock.patch.object(main, "NGSIEM", FakeNGSIEM):
        resp = router.route(main.Request(method="POST", url="/greynoise-ti-import-bulk", body={"api_key": "k"}),
                            logger=LOG)
    assert resp.code == 200
    assert resp.body["results"][0]["message"].startswith("Unchanged")
