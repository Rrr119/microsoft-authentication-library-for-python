"""Actionable diagnostics for token acquisition errors.

Token endpoint errors (notably ``invalid_grant`` during a token refresh)
are notoriously opaque: the same error code can mean an expired refresh
token, a revoked session, a new MFA policy, or simply a wrong device clock.
:func:`diagnose_error` classifies an error response by type and attaches a
concrete, actionable remediation hint.
"""

from .oauth2cli.clock_skew import is_clock_skew_error, ClockSkewCorrector


#: Diagnostic category constants
CLOCK_SKEW = "clock_skew"
REAUTHENTICATION_REQUIRED = "reauthentication_required"
INTERACTION_REQUIRED = "interaction_required"
CLIENT_CREDENTIAL_PROBLEM = "client_credential_problem"
UNAUTHORIZED_CLIENT = "unauthorized_client"
SCOPE_PROBLEM = "scope_problem"
THROTTLED = "throttled"
TRANSIENT_SERVER_ERROR = "transient_server_error"
UNKNOWN = "unknown"


def _clock_skew_advice(clock_skew_seconds):
    skew_note = (
        " A clock offset of approximately %+d seconds was detected and "
        "MSAL has applied automatic correction based on the server's "
        "Date header." % clock_skew_seconds
        ) if clock_skew_seconds else ""
    return (
        "The device clock appears to be out of sync with the identity "
        "server. Synchronize the device clock (e.g. via NTP) and retry."
        + skew_note)


def diagnose_error(response, clock_skew_seconds=None):
    """Classify a token error response and suggest an actionable remediation.

    :param dict response: An OAuth2 error response containing ``"error"``
        and optionally ``"error_description"`` etc..
    :param clock_skew_seconds: The currently measured clock skew, typically
        from ``ClockSkewCorrector.skew_seconds``. When a significant skew
        has been measured, ambiguous authentication errors are attributed
        to the clock.
    :return: A dict ``{"error", "error_type", "actionable_advice",
        "clock_skew_seconds"}``, or None if ``response`` is not an error.
    """
    if not isinstance(response, dict) or "error" not in response:
        return None
    error = response.get("error")
    significant_skew = (
        clock_skew_seconds is not None
        and abs(clock_skew_seconds) >= ClockSkewCorrector.DEFAULT_THRESHOLD_SECONDS)

    if is_clock_skew_error(response) or (
            significant_skew and error in ("invalid_grant", "invalid_client")):
        error_type = CLOCK_SKEW
        advice = _clock_skew_advice(clock_skew_seconds)
    elif error == "invalid_grant":
        error_type = REAUTHENTICATION_REQUIRED
        advice = (
            "The refresh token is expired, revoked, or no longer valid "
            "(e.g. due to a changed conditional access policy). "
            "Discard it and re-authenticate the user interactively.")
    elif error == "interaction_required":
        error_type = INTERACTION_REQUIRED
        advice = (
            "User interaction is required (e.g. consent or MFA). "
            "Retry with an interactive token acquisition.")
    elif error == "invalid_client":
        error_type = CLIENT_CREDENTIAL_PROBLEM
        advice = (
            "Client authentication failed. Verify the client secret or "
            "certificate is correct, not expired, and matches the app "
            "registration.")
    elif error == "unauthorized_client":
        error_type = UNAUTHORIZED_CLIENT
        advice = (
            "This client is not permitted to use the requested grant type. "
            "Review the app registration's enabled grant flows.")
    elif error == "invalid_scope":
        error_type = SCOPE_PROBLEM
        advice = (
            "One or more requested scopes are invalid, unknown, or not "
            "consented. Verify the scope list for this resource.")
    elif error == "too_many_requests":
        error_type = THROTTLED
        advice = (
            "The request was throttled. Honor the Retry-After response "
            "header and retry with backoff.")
    elif error in ("temporarily_unavailable", "service_unavailable"):
        error_type = TRANSIENT_SERVER_ERROR
        advice = (
            "Transient server-side error. Retry with exponential backoff; "
            "no change to credentials or cache is needed.")
    else:
        error_type = UNKNOWN
        advice = (
            "Unclassified error. Inspect error, error_description, "
            "correlation_id and timestamp in the response, and consult "
            "the identity server's error code documentation.")

    return {
        "error": error,
        "error_type": error_type,
        "actionable_advice": advice,
        "clock_skew_seconds": clock_skew_seconds,
        }
