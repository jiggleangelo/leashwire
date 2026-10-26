# Minimal RFC 8032 Ed25519 verifier, adapted from the public-domain reference algorithm.
import hashlib

q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493


def inv(x):
    return pow(x, q - 2, q)


d = -121665 * inv(121666) % q
I = pow(2, (q - 1) // 4, q)


def xrecover(y):
    x = pow((y * y - 1) * inv(d * y * y + 1) % q, (q + 3) // 8, q)
    if (x * x - (y * y - 1) * inv(d * y * y + 1)) % q:
        x = x * I % q
    return q - x if x & 1 else x


By = 4 * inv(5) % q
Bx = xrecover(By)
B = (Bx, By, 1, Bx * By % q)
IDENTITY = (0, 1, 1, 0)


def add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % q
    b = (y1 + x1) * (y2 + x2) % q
    c = 2 * d * t1 * t2 % q
    dd = 2 * z1 * z2 % q
    e = (b - a) % q
    f = (dd - c) % q
    g = (dd + c) % q
    h = (b + a) % q
    return e * f % q, g * h % q, f * g % q, e * h % q


def scalarmult(P, e):
    Q = IDENTITY
    while e:
        if e & 1:
            Q = add(Q, P)
        P = add(P, P)
        e >>= 1
    return Q


def equal(P, Q):
    return (
        P[0] * Q[2] % q == Q[0] * P[2] % q
        and P[1] * Q[2] % q == Q[1] * P[2] % q
    )


def decodepoint(s):
    if len(s) != 32:
        raise ValueError
    encoded = int.from_bytes(s, "little")
    y = encoded & ((1 << 255) - 1)
    if y >= q:
        raise ValueError
    x = xrecover(y)
    if (x * x - (y * y - 1) * inv(d * y * y + 1)) % q:
        raise ValueError
    if (x & 1) != (s[31] >> 7):
        x = q - x
    if x == 0 and (s[31] >> 7):
        raise ValueError
    P = (x, y, 1, x * y % q)
    # Extended/projective coordinates are equivalent up to their Z scale, so
    # subgroup membership must use projective equality rather than tuple equality.
    if not equal(scalarmult(P, l), IDENTITY):
        raise ValueError
    return P


def verify(public_key, message, signature):
    try:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        A = decodepoint(public_key)
        R = decodepoint(signature[:32])
        S = int.from_bytes(signature[32:], "little")
        if S >= l:
            return False
        h = int.from_bytes(
            hashlib.sha512(signature[:32] + public_key + message).digest(),
            "little",
        ) % l
        return equal(scalarmult(B, S), add(R, scalarmult(A, h)))
    except (ValueError, TypeError):
        return False
