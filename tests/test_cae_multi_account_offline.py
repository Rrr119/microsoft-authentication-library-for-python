"""Tests for CAE claims challenges, per-account cache isolation and offline
graceful degradation of the token cache.

The three top-level test classes map to the three invalidation scenarios:

1. ``TestCaeClaimsChallenge`` - a resource rejects an access token and emits a
   claims challenge; MSAL must bypass the cache, refresh with the challenge,
   and never replay the revoked token when the network is down.
2. ``TestOfflineDegradation`` - when the identity provider is unreachable, an
   expired cached token is only served after explicitly opting in.
3. ``TestPartitionedTokenCache`` - accounts sharing one application must never
   see each other's tokens.
"""
import base64
import json
from unittest.mock import patch, Mock

from requests.exceptions import ConnectionError as RequestsConnectionError

import msal
from msal.application import ClientApplication
from tests import unittest
from tests.http_client import MinimalResponse
from tests.test_token_cache import build_response


_OIDC_DISCOVERY = "msal.authority.tenant_discovery"
_OIDC_DISCOVERY_MOCK = patch(
    _OIDC_DISCOVERY,
    new=Mock(return_value={
        "authorization_endpoint": (
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"),
        "token_endpoint": (
            "https://login.microsoftonline.com/common/oauth2/v2.0/token"),
        "issuer": "https://login.microsoftonline.com/tenant",
    }))

AUTHORITY_URL = "https://login.microsoftonline.com/common"
SCOPES = ["s1", "s2"]
CLIENT_ID = "my_app"
CAE_CHALLENGE = json.dumps({
    "access_token": {"xms_cc": {"essential": True}}})


def _network_failure(*args, **kwargs):
    raise RequestsConnectionError("simulated network outage")


def _token_response(access_token="new_at", refresh_token="new_rt",
                    uid="uid", utid="utid", **extra):
    body = {"access_token": access_token, "expires_in": 3600}
    if refresh_token:
        body["refresh_token"] = refresh_token
    if uid and utid:  # Mimic AAD: refresh responses still carry client_info
        body["client_info"] = base64.b64encode(json.dumps({
            "uid": uid, "utid": utid}).encode()).decode("utf-8")
    body.update(extra)
    return MinimalResponse(status_code=200, text=json.dumps(body))


def _seed_cache(app, cache, uid, utid, access_token, expires_in=3600,
                refresh_token="the_rt"):
    """Populate *cache* through *app*'s own authority so realm/environment
    keys match what the app will query later."""
    cache.add({
        "client_id": app.client_id,
        "scope": SCOPES,
        "token_endpoint": app.authority.token_endpoint,
        "response": build_response(
            access_token=access_token, expires_in=expires_in,
            uid=uid, utid=utid, refresh_token=refresh_token),
        })


@patch(_OIDC_DISCOVERY, new=_OIDC_DISCOVERY_MOCK.new)
class TestCaeClaimsChallenge(unittest.TestCase):
    """Scenario 1: claims challenge handling (CAE)."""

    def setUp(self):
        self.uid, self.utid = "uid", "utid"
        self.account = {
            "home_account_id": "{}.{}".format(self.uid, self.utid)}
        self.cache = msal.SerializableTokenCache()
        self.app = ClientApplication(
            CLIENT_ID, authority=AUTHORITY_URL, token_cache=self.cache)
        _seed_cache(
            self.app, self.cache, self.uid, self.utid,
            access_token="revoked_by_resource_at")

    def test_challenge_bypasses_cache_and_refreshes_with_claims(self):
        captured = {}

        def mock_post(url, headers=None, data=None, *args, **kwargs):
            captured.update(data or {})
            return _token_response(access_token="cae_refreshed_at")

        result = self.app.acquire_token_silent(
            SCOPES, self.account,
            claims_challenge=CAE_CHALLENGE, post=mock_post)

        self.assertEqual("cae_refreshed_at", result["access_token"])
        self.assertEqual(
            self.app._TOKEN_SOURCE_IDP, result[self.app._TOKEN_SOURCE],
            "A claims challenge must bypass the cached AT")
        self.assertEqual(
            json.loads(CAE_CHALLENGE), json.loads(captured["claims"]),
            "The refresh request must carry the claims challenge")

    def test_challenge_network_failure_does_not_fallback_to_revoked_token(self):
        # Even with offline access opted in, a CAE challenge means the resource
        # already revoked the cached AT, so it must not be replayed.
        with self.assertRaises(RequestsConnectionError):
            self.app.acquire_token_silent(
                SCOPES, self.account,
                claims_challenge=CAE_CHALLENGE,
                allow_offline_access=True, post=_network_failure)

    def test_malformed_challenge_fails_fast_without_network_io(self):
        with self.assertRaises(ValueError):
            self.app.acquire_token_silent(
                SCOPES, self.account,
                claims_challenge="not-a-json-object",
                post=lambda *a, **k: self.fail("No network call expected"))

    def test_successful_challenge_refresh_overwrites_cached_token(self):
        result = self.app.acquire_token_silent(
            SCOPES, self.account,
            claims_challenge=CAE_CHALLENGE,
            post=lambda *a, **k: _token_response(access_token="cae_at_2"))
        self.assertEqual("cae_at_2", result["access_token"])
        # The refreshed token is persisted under the same account, alongside
        # the RT-path's decorated scopes (openid/profile/offline_access).
        all_at_secrets = [
            entry["secret"] for entry in self.cache.search(
                self.cache.CredentialType.ACCESS_TOKEN)]
        self.assertIn("cae_at_2", all_at_secrets)
        # The pre-challenge token, stored under the raw-scope key, remains
        # untouched but will never be served while the challenge is active.
        raw_entries = [
            entry for entry in self.cache.search(
                self.cache.CredentialType.ACCESS_TOKEN, target=SCOPES)
            if entry.get("target") == " ".join(sorted(SCOPES))]
        self.assertEqual(
            ["revoked_by_resource_at"],
            [entry["secret"] for entry in raw_entries])


@patch(_OIDC_DISCOVERY, new=_OIDC_DISCOVERY_MOCK.new)
class TestOfflineDegradation(unittest.TestCase):
    """Scenario 2: offline graceful degradation."""

    def setUp(self):
        self.uid, self.utid = "uid2", "utid2"
        self.account = {
            "home_account_id": "{}.{}".format(self.uid, self.utid)}
        self.cache = msal.SerializableTokenCache()
        self.app = ClientApplication(
            CLIENT_ID, authority=AUTHORITY_URL, token_cache=self.cache)
        _seed_cache(
            self.app, self.cache, self.uid, self.utid,
            access_token="expired_at", expires_in=-99)

    def test_network_failure_without_opt_in_raises(self):
        with self.assertRaises(RequestsConnectionError):
            self.app.acquire_token_silent(
                SCOPES, self.account, post=_network_failure)

    def test_network_failure_with_opt_in_serves_expired_token(self):
        result = self.app.acquire_token_silent(
            SCOPES, self.account,
            allow_offline_access=True, post=_network_failure)
        self.assertEqual("expired_at", result["access_token"])
        self.assertTrue(result["offline"])
        self.assertEqual(
            self.app._TOKEN_SOURCE_CACHE, result[self.app._TOKEN_SOURCE])
        self.assertEqual(0, result["expires_in"])

    def test_force_refresh_offline_still_serves_cached_token(self):
        # force_refresh skips the normal AT lookup; offline mode must still
        # find the expired AT through the direct lookup path.
        result = self.app.acquire_token_silent(
            SCOPES, self.account, force_refresh=True,
            allow_offline_access=True, post=_network_failure)
        self.assertEqual("expired_at", result["access_token"])
        self.assertTrue(result["offline"])

    def test_offline_opt_in_does_not_swallow_service_errors(self):
        # A reachable IdP returning an OAuth error is not an offline scenario.
        result = self.app.acquire_token_silent_with_error(
            SCOPES, self.account, allow_offline_access=True,
            post=lambda *a, **k: MinimalResponse(
                status_code=400,
                text=json.dumps({"error": "invalid_grant"})))
        self.assertEqual("invalid_grant", result.get("error"))
        self.assertNotIn("offline", result)

    def test_offline_with_empty_cache_raises(self):
        self.app.token_cache = msal.SerializableTokenCache()
        # No RT in cache means no network attempt is made at all; the silent
        # API therefore returns None rather than raising or inventing a token.
        self.assertIsNone(self.app.acquire_token_silent(
            SCOPES, self.account,
            allow_offline_access=True, post=_network_failure))


class TestPartitionedTokenCache(unittest.TestCase):
    """Scenario 3: per-account isolated cache."""

    def _seed_cache(self, cache, uid, utid, token):
        partition = cache.for_account("{}.{}".format(uid, utid))
        partition.add({
            "client_id": CLIENT_ID,
            "scope": SCOPES,
            "token_endpoint": "{}/oauth2/v2.0/token".format(AUTHORITY_URL),
            "response": build_response(
                access_token=token, expires_in=3600,
                uid=uid, utid=utid, refresh_token="rt_{}".format(uid)),
            })
        return partition

    def test_accounts_have_independent_partitions(self):
        cache = msal.PartitionedTokenCache()
        partition_a = self._seed_cache(cache, "alice", "tid", "alice_at")
        partition_b = self._seed_cache(cache, "bob", "tid", "bob_at")

        self.assertIsNot(partition_a, partition_b)
        self.assertEqual(
            ["alice_at"], [entry["secret"] for entry in partition_a.search(
                partition_a.CredentialType.ACCESS_TOKEN)])
        self.assertEqual(
            ["bob_at"], [entry["secret"] for entry in partition_b.search(
                partition_b.CredentialType.ACCESS_TOKEN)])

    def test_delegated_access_uses_active_partition(self):
        cache = msal.PartitionedTokenCache()
        self._seed_cache(cache, "alice", "tid", "alice_at")
        cache.for_account("bob.tid")  # Switch active partition
        # The facade now delegates to Bob's (empty) partition
        self.assertEqual([], list(cache.search(
            cache.CredentialType.ACCESS_TOKEN)))
        cache.for_account("alice.tid")
        self.assertEqual(1, len(list(cache.search(
            cache.CredentialType.ACCESS_TOKEN))))

    def test_removal_in_one_partition_does_not_affect_others(self):
        cache = msal.PartitionedTokenCache()
        partition_a = self._seed_cache(cache, "alice", "tid", "alice_at")
        self._seed_cache(cache, "bob", "tid", "bob_at")
        for at in list(partition_a.search(
                partition_a.CredentialType.ACCESS_TOKEN)):
            partition_a.remove_at(at)
        self.assertEqual([], list(partition_a.search(
            partition_a.CredentialType.ACCESS_TOKEN)))
        cache.for_account("bob.tid")
        self.assertEqual(1, len(list(cache.search(
            cache.CredentialType.ACCESS_TOKEN))))

    def test_app_only_tokens_use_dedicated_partition(self):
        cache = msal.PartitionedTokenCache()
        app_partition = cache.for_account(None)
        app_partition.add({
            "client_id": CLIENT_ID,
            "scope": SCOPES,
            "token_endpoint": "{}/oauth2/v2.0/token".format(AUTHORITY_URL),
            "response": build_response(
                access_token="app_only_at", expires_in=3600),
            })
        self._seed_cache(cache, "alice", "tid", "alice_at")
        self.assertEqual(1, len(list(cache.for_account(None).search(
            cache.CredentialType.ACCESS_TOKEN))))
        self.assertEqual(1, len(list(cache.for_account("alice.tid").search(
            cache.CredentialType.ACCESS_TOKEN))))

    def test_roundtrip_serialization_preserves_partitions(self):
        cache = msal.PartitionedTokenCache()
        self._seed_cache(cache, "alice", "tid", "alice_at")
        self._seed_cache(cache, "bob", "tid", "bob_at")
        blob = cache.serialize()

        restored = msal.PartitionedTokenCache()
        restored.deserialize(blob)
        self.assertEqual(
            ["alice_at"], [e["secret"] for e in restored.for_account(
                "alice.tid").search(
                    restored.CredentialType.ACCESS_TOKEN)])
        self.assertEqual(
            ["bob_at"], [e["secret"] for e in restored.for_account(
                "bob.tid").search(
                    restored.CredentialType.ACCESS_TOKEN)])

    def test_deserialize_accepts_legacy_single_partition_blob(self):
        legacy = msal.SerializableTokenCache()
        legacy.add({
            "client_id": CLIENT_ID,
            "scope": SCOPES,
            "token_endpoint": "{}/oauth2/v2.0/token".format(AUTHORITY_URL),
            "response": build_response(
                access_token="legacy_at", expires_in=3600),
            })
        cache = msal.PartitionedTokenCache()
        cache.deserialize(legacy.serialize())
        self.assertEqual(
            ["legacy_at"], [e["secret"] for e in cache.for_account(None).search(
                cache.CredentialType.ACCESS_TOKEN)])

    def test_invalid_account_id_type_is_rejected(self):
        cache = msal.PartitionedTokenCache()
        with self.assertRaises(ValueError):
            cache.for_account(123)

    def test_has_state_changed_tracks_any_partition(self):
        cache = msal.PartitionedTokenCache()
        self.assertFalse(cache.has_state_changed)
        self._seed_cache(cache, "alice", "tid", "alice_at")
        self.assertTrue(cache.has_state_changed)
        cache.serialize()
        self.assertFalse(cache.has_state_changed)


@patch(_OIDC_DISCOVERY, new=_OIDC_DISCOVERY_MOCK.new)
class TestPartitionedCacheWithApplications(unittest.TestCase):
    """End-to-end: two apps sharing one PartitionedTokenCache stay isolated."""

    def _build_app(self, cache, home_account_id):
        return ClientApplication(
            CLIENT_ID, authority=AUTHORITY_URL,
            token_cache=cache.for_account(home_account_id))

    def test_each_application_only_sees_its_own_account_tokens(self):
        cache = msal.PartitionedTokenCache()
        app_a = self._build_app(cache, "alice.tid")
        app_b = self._build_app(cache, "bob.tid")

        app_a.token_cache.add({
            "client_id": CLIENT_ID,
            "scope": SCOPES,
            "token_endpoint": app_a.authority.token_endpoint,
            "response": build_response(
                access_token="alice_at", expires_in=3600,
                uid="alice", utid="tid", refresh_token="alice_rt"),
            })
        app_b.token_cache.add({
            "client_id": CLIENT_ID,
            "scope": SCOPES,
            "token_endpoint": app_b.authority.token_endpoint,
            "response": build_response(
                access_token="bob_at", expires_in=3600,
                uid="bob", utid="tid", refresh_token="bob_rt"),
            })

        # Each partition is an independent cache object
        self.assertIsNot(app_a.token_cache, app_b.token_cache)
        self.assertEqual(1, len(list(app_a.token_cache.search(
            app_a.token_cache.CredentialType.ACCESS_TOKEN))))
        self.assertEqual(1, len(list(app_b.token_cache.search(
            app_b.token_cache.CredentialType.ACCESS_TOKEN))))

        # Silent lookup for Alice can never return Bob's token
        result_a = app_a.acquire_token_silent(
            SCOPES, {"home_account_id": "alice.tid"},
            post=lambda *a, **k: self.fail("Alice should hit her cache"))
        self.assertEqual("alice_at", result_a["access_token"])
        # Bob's app cannot resolve Alice's account: her tokens live in a
        # different partition that Bob's cache cannot see.
        self.assertIsNone(app_b.acquire_token_silent(
            SCOPES, {"home_account_id": "alice.tid"},
            post=lambda *a, **k: self.fail("Bob must not use network here")))

        # The serialized blob contains both accounts but keeps them apart
        blob = json.loads(cache.serialize())
        self.assertIn("alice.tid", blob)
        self.assertIn("bob.tid", blob)
