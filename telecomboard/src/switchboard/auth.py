"""DEV-ONLY identity provider: RS256 JWTs, JWKS, RFC 8693-style token exchange (audience-bound, act claim)."""
from __future__ import annotations

import json
import secrets

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .context import Principal
from .core import connect, data_dir, now

ISSUER = "switchboard-dev-idp"
GATEWAY_AUD = "switchboard-gateway"
KID = "dev-1"
_priv = None


def _key():
    global _priv
    if _priv is None:
        path = data_dir() / "idp_key.pem"
        if path.exists():
            _priv = serialization.load_pem_private_key(path.read_bytes(), password=None)
        else:
            _priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            path.write_bytes(_priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()))
    return _priv


def jwks() -> dict:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(_key().public_key()))
    return {"keys": [{**jwk, "kid": KID, "use": "sig", "alg": "RS256"}]}


def _user(user_id: str) -> dict:
    with connect("platform") as c:
        row = c.execute("SELECT role, tenant FROM app_user WHERE user_id=?", (user_id,)).fetchone()
    if row is None:
        raise PermissionError("unknown user")
    return dict(row)


def issue(user_id: str, audience: str = GATEWAY_AUD, ttl: int = 900, **extra) -> str:
    u, t = _user(user_id), int(now())
    claims = {"iss": ISSUER, "sub": user_id, "aud": audience, "iat": t, "exp": t + ttl, "auth_time": t,
              "jti": secrets.token_hex(8), "role": u["role"], "tenant": u["tenant"], **extra}
    return jwt.encode(claims, _key(), algorithm="RS256", headers={"kid": KID})


def verify(token: str, audience: str) -> dict:
    return jwt.decode(token, _key().public_key(), algorithms=["RS256"], audience=audience, issuer=ISSUER,
                      options={"require": ["exp", "iat", "sub", "aud"]}, leeway=5)


def exchange(subject_token: str, audience: str, scopes: list[str], actor: str = "orchestrator") -> str:
    """Narrow a user token to a downstream audience. User tokens are never forwarded verbatim."""
    c = verify(subject_token, GATEWAY_AUD)
    t = int(now())
    claims = {"iss": ISSUER, "sub": c["sub"], "aud": audience, "iat": t, "exp": t + 300,
              "auth_time": c.get("auth_time"), "role": c["role"], "tenant": c["tenant"],
              "scope": " ".join(scopes), "act": {"sub": actor}, "jti": secrets.token_hex(8)}
    return jwt.encode(claims, _key(), algorithm="RS256", headers={"kid": KID})


def principal_from_token(token: str, audience: str = GATEWAY_AUD) -> Principal:
    c = verify(token, audience)
    # A valid old token must not preserve privileges after a directory role change.
    current = _user(c["sub"])
    return Principal(user_id=c["sub"], role=current["role"], tenant=current["tenant"],
                     token=token, auth_time=c.get("auth_time"))
