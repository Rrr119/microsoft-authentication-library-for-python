"""Acceptance tests for clock skew detection/correction and diagnostics.

Simulates a device clock that is accurate, 30 minutes fast, or 30 minutes
slow, and verifies that:
* token refresh still succeeds in all 3 scenarios,
* cached token timestamps are computed against the server clock,
* the diagnostics reach the correct conclusion per scenario,
* the no-skew (normal) path keeps its legacy cache behavior exactly.
"""

import json
import logging
import time
from email.utils import formatdate
from unittest.mock import patch, Mock

import msal
from msal import TokenCache
from msal.oauth2cli import Client
from msal.oauth2cli.clock_skew import ClockSkewCorrector, is_clock_skew_error
from msal.diagnostics import diagnose_error
from tests import unittest
from tests.http_client import MinimalHttpClient, MinimalResponse
from tests.test_token_cache import build_response


logger = logging.getLogger(__name__)

REAL_TIME = time.time  # Unaffected by patching, represents the server clock
THIRTY_MINUTES = 30 * 60

_OIDC_DISCOVERY = "msal.authority.tenant_discovery"
_OIDC_DISCOVERY_MOCK = Mock(return_value={
    "authorization_endpoint": "https://contoso.com/placeholder",
    "token_endpoint": "https://contoso.com/placeholder",
    "issuer": "https://contoso.com/tenant",
})


def _http_date(epoch):
    return formatdate(epoch, usegmt=True)


class TestClockSkewCorrector(unittest.TestCase):

    def test_no_date_header_means_no_detection(self):
        corrector = ClockSkewCorrector()
        self.assertFalse(corrector.observe_response_headers(None))
        self.assertFalse(corrector.observe_response_headers({}))
        self.assertFalse(corrector.observe_response_headers({"Date": "garbage"}))
        self.assertEqual(0, corrector.skew_seconds)
        self.assertFalse(corrector.correction_active)

    def test_small_skew_is_tolerated_and_not_applied(self):
        corrector = ClockSkewCorrector()
        self.assertTrue(corrector.observe_response_headers(
            {"Date": _http_date(REAL_TIME() + 30)}))  # 30s fast
        self.assertFalse(corrector.correction_active)
        self.assertAlmostEqual(corrector.now(), REAL_TIME(), delta=2)

    def test_large_skew_is_detected_and_corrected(self):
        corrector = ClockSkewCorrector()
        corrector.observe_response_headers(
            {"date": _http_date(REAL_TIME() + THIRTY_MINUTES)})  # lowercase
        self.assertTrue(corrector.correction_active)
        self.assertAlmostEqual(corrector.skew_seconds, THIRTY_MINUTES, delta=2)
        self.assertAlmostEqual(
            corrector.now(), REAL_TIME() + THIRTY_MINUTES, delta=2)

    def test_is_clock_skew_error(self):
        self.assertTrue(is_clock_skew_error({
            "error": "invalid_client",
            "error_description": "AADSTS700024: Client assertion is expired."}))
        self.assertTrue(is_clock_skew_error({
            "error": "invalid_grant",
            "error_description": "The token is not yet valid."}))
        self.assertFalse(is_clock_skew_error({
            "error": "invalid_grant", "error_description": "Bad token."}))
        self.assertFalse(is_clock_skew_error(None))


class TestRefreshUnderClockSkew(unittest.TestCase):
    """The 3-scenario acceptance: no offset, +30min (fast), -30min (slow)."""

    def _refresh_once(self, offset):
        """Run one token refresh with the device clock shifted by ``offset``."""
        cache = TokenCache()
        captured_events = []
        server_now = REAL_TIME()  # The authority's clock never drifts

        def fake_post(url, **kwargs):
            return MinimalResponse(
                status_code=200,
                headers={"Date": _http_date(server_now)},
                text=json.dumps({
                    "access_token": "AT-from-offset-%d" % offset,
                    "expires_in": 3600,
                    "refresh_token": "new RT",
                    "token_type": "Bearer",
                    }))

        client = Client(
            {"token_endpoint": "https://contoso.com/token"},
            "client_id",
            http_client=MinimalHttpClient(),
            on_obtaining_tokens=lambda event: (
                captured_events.append(dict(event)),
                cache.add(dict(event, environment="contoso.com")),
                )[1],
            )
        with patch("time.time",  # Simulate the drifting device clock
                side_effect=lambda: REAL_TIME() + offset):
            result = client.obtain_token_by_refresh_token(
                "old RT", scope=["s1"], post=fake_post)
        return result, cache, captured_events, server_now

    def test_refresh_succeeds_under_all_three_offsets(self):
        outcomes = {}
        for offset in (0, THIRTY_MINUTES, -THIRTY_MINUTES):
            with self.subTest(offset=offset):
                result, cache, events, server_now = self._refresh_once(offset)
                outcomes[offset] = "access_token" in result
                self.assertIn(
                    "access_token", result,
                    "Refresh should succeed with offset %d" % offset)
                at_entries = cache.find(
                    TokenCache.CredentialType.ACCESS_TOKEN,
                    query={"client_id": "client_id"})
                self.assertEqual(1, len(at_entries))
                entry = at_entries[0]
                # expires_on must be anchored to the SERVER clock,
                # regardless of the device clock drift.
                self.assertAlmostEqual(
                    int(entry["expires_on"]), int(server_now) + 3600, delta=3)
        success_rate = sum(outcomes.values()) / float(len(outcomes))
        logger.info("Refresh success rate: %s", success_rate)
        self.assertEqual(1.0, success_rate)

    def test_no_offset_keeps_legacy_cache_behavior(self):
        result, cache, events, server_now = self._refresh_once(0)
        self.assertIn("access_token", result)
        self.assertEqual(1, len(events))
        self.assertNotIn(  # No correction -> event identical to legacy MSAL
            "now", events[0],
            "Normal path must not inject a corrected timestamp")
        entry = cache.find(
            TokenCache.CredentialType.ACCESS_TOKEN,
            query={"client_id": "client_id"})[0]
        # Legacy behavior: timestamps derived from the local clock
        self.assertAlmostEqual(int(entry["cached_at"]), int(server_now), delta=3)
        self.assertAlmostEqual(
            int(entry["expires_on"]), int(server_now) + 3600, delta=3)

    def test_skewed_clock_triggers_correction_in_cache_event(self):
        for offset in (THIRTY_MINUTES, -THIRTY_MINUTES):
            with self.subTest(offset=offset):
                _, _, events, server_now = self._refresh_once(offset)
                self.assertIn("now", events[0])
                self.assertAlmostEqual(events[0]["now"], server_now, delta=3)


class TestDiagnostics(unittest.TestCase):

    def test_clock_skew_error_is_identified_by_error_code(self):
        diagnostic = diagnose_error({
            "error": "invalid_client",
            "error_description": "AADSTS700024: Client assertion is expired.",
            })
        self.assertEqual("clock_skew", diagnostic["error_type"])
        self.assertIn("clock", diagnostic["actionable_advice"].lower())

    def test_ambiguous_refresh_failure_attributed_by_measured_skew(self):
        response = {"error": "invalid_grant", "error_description": "xyz"}
        # With a significant measured skew, blame the clock
        diagnostic = diagnose_error(response, clock_skew_seconds=THIRTY_MINUTES)
        self.assertEqual("clock_skew", diagnostic["error_type"])
        self.assertEqual(THIRTY_MINUTES, diagnostic["clock_skew_seconds"])
        # Without skew, the same error means: re-authenticate
        diagnostic = diagnose_error(response, clock_skew_seconds=0)
        self.assertEqual("reauthentication_required", diagnostic["error_type"])
        self.assertIn("re-authenticate", diagnostic["actionable_advice"])

    def test_error_types_map_to_actionable_advice(self):
        expectations = {
            "interaction_required": "interaction_required",
            "invalid_client": "client_credential_problem",
            "unauthorized_client": "unauthorized_client",
            "invalid_scope": "scope_problem",
            "too_many_requests": "throttled",
            "temporarily_unavailable": "transient_server_error",
            "service_unavailable": "transient_server_error",
            "something_never_seen": "unknown",
            }
        for error, expected_type in expectations.items():
            with self.subTest(error=error):
                diagnostic = diagnose_error({"error": error})
                self.assertEqual(expected_type, diagnostic["error_type"])
                self.assertTrue(diagnostic["actionable_advice"])

    def test_non_error_response_yields_no_diagnostic(self):
        self.assertIsNone(diagnose_error({"access_token": "ok"}))
        self.assertIsNone(diagnose_error(None))


class TestAppLevelRefreshUnderClockSkew(unittest.TestCase):
    """End-to-end: ClientApplication refresh with a drifting device clock."""

    @patch(_OIDC_DISCOVERY, new=_OIDC_DISCOVERY_MOCK)
    def setUp(self):
        self.authority_url = "https://login.microsoftonline.com/common"
        self.scopes = ["s1", "s2"]
        self.uid, self.utid = "my_uid", "my_utid"
        self.account = {"home_account_id": "%s.%s" % (self.uid, self.utid)}
        self.client_id = "my_app"
        self.cache = msal.SerializableTokenCache()
        self.cache.add({  # Pre-populate with an expired AT and a valid RT
            "client_id": self.client_id,
            "scope": self.scopes,
            "token_endpoint": "%s/oauth2/v2.0/token" % self.authority_url,
            "response": build_response(
                access_token="an expired AT to trigger refresh", expires_in=-99,
                uid=self.uid, utid=self.utid, refresh_token="this is a RT"),
            })
        self.app = msal.ClientApplication(
            self.client_id, authority=self.authority_url,
            token_cache=self.cache)

    def _run_refresh(self, offset, response_text, status_code=200):
        server_now = REAL_TIME()

        def fake_post(url, **kwargs):
            return MinimalResponse(
                status_code=status_code,
                headers={"Date": _http_date(server_now)},
                text=response_text)

        with patch("time.time", side_effect=lambda: REAL_TIME() + offset):
            with self.assertLogs("msal.application", level="DEBUG") as logs:
                result = self.app.acquire_token_silent_with_error(
                    self.scopes, self.account, post=fake_post)
        return result, server_now, "\n".join(logs.output)

    def test_refresh_succeeds_under_all_three_offsets(self):
        successes = 0
        for offset in (0, THIRTY_MINUTES, -THIRTY_MINUTES):
            with self.subTest(offset=offset):
                result, server_now, _ = self._run_refresh(offset, json.dumps(
                    build_response(
                        access_token="fresh AT", expires_in=3600,
                        uid=self.uid, utid=self.utid,
                        refresh_token="new RT")))
                if "access_token" in result:
                    successes += 1
                self.assertIn("access_token", result)
                new_at = [e for e in self.cache.find(
                    TokenCache.CredentialType.ACCESS_TOKEN,
                    query={"client_id": self.client_id})
                    if e["secret"] == "fresh AT"]
                self.assertEqual(1, len(new_at))
                self.assertAlmostEqual(
                    int(new_at[0]["expires_on"]), int(server_now) + 3600,
                    delta=3)
        self.assertEqual(3, successes, "Refresh success rate should be 3/3")

    def test_diagnostics_conclusion_matches_each_offset(self):
        error_response = json.dumps({
            "error": "invalid_grant", "error_description": "xyz"})
        for offset, expected_type in (
                (0, "reauthentication_required"),
                (THIRTY_MINUTES, "clock_skew"),
                (-THIRTY_MINUTES, "clock_skew"),
                ):
            with self.subTest(offset=offset):
                result, _, logs = self._run_refresh(offset, error_response, 400)
                self.assertEqual("invalid_grant", result.get("error"))
                self.assertIn(
                    "Diagnostics (%s)" % expected_type, logs,
                    "Refresh failure log should carry actionable diagnostics")
                # The same conclusion is available programmatically
                diagnostic = diagnose_error(
                    result,
                    clock_skew_seconds=(
                        self.app._clock_skew_corrector.skew_seconds))
                self.assertEqual(expected_type, diagnostic["error_type"])

    def test_normal_path_cache_behavior_unchanged(self):
        result, server_now, _ = self._run_refresh(0, json.dumps(
            build_response(
                access_token="fresh AT", expires_in=3600,
                uid=self.uid, utid=self.utid, refresh_token="new RT")))
        self.assertIn("access_token", result)
        self.assertFalse(
            self.app._clock_skew_corrector.correction_active,
            "No correction should kick in when the clock is accurate")
        new_at = [e for e in self.cache.find(
            TokenCache.CredentialType.ACCESS_TOKEN,
            query={"client_id": self.client_id})
            if e["secret"] == "fresh AT"][0]
        # Legacy behavior: cached_at/expires_on anchored to local time
        self.assertAlmostEqual(int(new_at["cached_at"]), int(server_now), delta=3)
        self.assertAlmostEqual(
            int(new_at["expires_on"]), int(server_now) + 3600, delta=3)


if __name__ == "__main__":
    unittest.main()
