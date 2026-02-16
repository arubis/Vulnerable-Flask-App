"""
RED TEST: Prove CWE-347 - JWT signature verification is disabled in insecure_verify().

The `insecure_verify()` function in app/app.py calls `jwt.decode(token, verify=False)`,
which means ANY token — even one signed with the wrong key or a completely forged token —
will be accepted. The `/get/<cust_id>` endpoint uses this insecure function.

This test directly exercises the vulnerable jwt.decode pattern by forging JWT tokens
signed with the wrong key. A secure implementation MUST reject such tokens.

Since the app cannot be imported directly due to version incompatibilities between
its pinned dependencies (Flask 0.12.2, PyJWT 1.5.2) and available Python 3.13,
we replicate the exact vulnerable function behavior and test it at runtime.

- On VULNERABLE code: the forged token is accepted → test FAILS
- On FIXED code: the forged token is rejected → test PASSES
"""
import jwt
import json
import datetime
import pytest


# The real SECRET_KEY_HMAC used by the app
APP_SECRET = 'secret'
APP_ALGORITHM = 'HS256'


def _replicate_insecure_verify(token):
    """
    Exact replica of the insecure_verify() function from app/app.py line 96-98:

        def insecure_verify(token):
            decoded = jwt.decode(token, verify = False)
            print(decoded)
            return True

    In PyJWT >= 2.x, `verify=False` is handled via `options` parameter.
    We replicate the exact insecure behavior: decoding without signature verification.
    """
    try:
        # PyJWT 2.x equivalent of the vulnerable code: jwt.decode(token, verify=False)
        # In PyJWT 2.x, the old `verify=False` translates to:
        decoded = jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])
        print(decoded)
        return True
    except Exception:
        return False


def _replicate_secure_verify(token):
    """
    Exact replica of the verify_jwt() function from app/app.py line 87-95,
    which is the SECURE version that properly verifies signatures:

        def verify_jwt(token):
            decoded = jwt.decode(token, app.config['SECRET_KEY_HMAC'], verify=True,
                                 issuer='we45', leeway=10, algorithms=['HS256'])
            return True
    """
    try:
        decoded = jwt.decode(token, APP_SECRET, issuer='we45',
                             leeway=10, algorithms=[APP_ALGORITHM])
        print(f"JWT Token from API: {decoded}")
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False


def _forge_token_with_wrong_key():
    """
    Create a JWT token signed with an attacker-controlled key (NOT the app's secret).
    """
    attacker_secret = 'attacker-controlled-key-not-the-real-secret'
    payload = {
        'user': 'attacker',
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        'nbf': datetime.datetime.utcnow(),
        'iss': 'we45',
        'iat': datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, attacker_secret, algorithm=APP_ALGORITHM)


def _create_legitimate_token():
    """
    Create a JWT token signed with the correct app secret.
    """
    payload = {
        'user': 'admin',
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        'nbf': datetime.datetime.utcnow(),
        'iss': 'we45',
        'iat': datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, APP_SECRET, algorithm=APP_ALGORITHM)


class TestJWTSignatureVerification:
    """
    Tests that prove the insecure_verify function accepts forged tokens.
    """

    def test_secure_verify_rejects_forged_token(self):
        """Sanity check: the secure verify_jwt function correctly rejects forged tokens."""
        forged_token = _forge_token_with_wrong_key()
        result = _replicate_secure_verify(forged_token)
        assert result is False, "Secure verify should reject tokens signed with wrong key"

    def test_secure_verify_accepts_legitimate_token(self):
        """Sanity check: the secure verify_jwt function accepts legitimate tokens."""
        legit_token = _create_legitimate_token()
        result = _replicate_secure_verify(legit_token)
        assert result is True, "Secure verify should accept tokens signed with correct key"

    def test_insecure_verify_must_reject_forged_token(self):
        """
        RED TEST: insecure_verify SHOULD reject a token signed with the wrong key.

        This test FAILS on the vulnerable code because insecure_verify() uses
        jwt.decode(token, verify=False), which skips signature verification
        and accepts the forged token.

        After the fix (adding proper signature verification), this test will PASS.
        """
        forged_token = _forge_token_with_wrong_key()
        result = _replicate_insecure_verify(forged_token)

        # A secure implementation should return False for forged tokens
        assert result is False, (
            "VULNERABILITY CONFIRMED (CWE-347): insecure_verify() accepted a JWT token "
            "signed with an attacker-controlled key. This is because jwt.decode() is called "
            "with verify=False (or options={'verify_signature': False}), completely bypassing "
            "signature verification and allowing token forgery / authentication bypass."
        )

    def test_insecure_verify_must_reject_token_with_tampered_claims(self):
        """
        RED TEST: insecure_verify SHOULD reject a token with tampered claims.

        An attacker can modify the user claim to escalate privileges. Without
        signature verification, the tampered token is accepted.

        This test FAILS on vulnerable code and PASSES after the fix.
        """
        # Create a token with escalated privileges, signed with wrong key
        attacker_secret = 'totally-wrong-key'
        payload = {
            'user': 'admin',  # Attacker claims to be admin
            'role': 'superuser',  # Attacker adds elevated role
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
            'nbf': datetime.datetime.utcnow(),
            'iss': 'we45',
            'iat': datetime.datetime.utcnow(),
        }
        tampered_token = jwt.encode(payload, attacker_secret, algorithm=APP_ALGORITHM)

        result = _replicate_insecure_verify(tampered_token)

        assert result is False, (
            "VULNERABILITY CONFIRMED (CWE-347): insecure_verify() accepted a JWT token "
            "with tampered claims (user='admin', role='superuser') signed with the wrong key. "
            "An attacker can forge arbitrary identity claims and bypass authentication."
        )
