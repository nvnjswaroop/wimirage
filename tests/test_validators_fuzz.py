"""Property-based fuzz tests for core.captive_portal validators.

Section 7 #3 — protect the form-level security boundary with Hypothesis.
These run with pytest; if `hypothesis` is not installed in CI they will
auto-skip via the `@pytest.mark.skipif` guard rather than fail the build.
"""

import pytest

try:
    from hypothesis import given, settings, strategies as st

    HAVE_HYPOTHESIS = True
except ImportError:  # pragma: no cover
    HAVE_HYPOTHESIS = False

    # No-op fallbacks so the ``@settings`` / ``@given`` decorators below
    # still evaluate at collection time without crashing the whole suite
    # run (the module is skipped wholesale via pytestmark). Without these,
    # a missing package used to raise NameError during *collection* —
    # killing every other test file too, instead of skipping just this one.
    def settings(*_a, **_kw):
        def _wrap(fn):
            return fn

        return _wrap

    def given(*_a, **_kw):
        def _wrap(fn):
            return lambda *args, **kwargs: None

        return _wrap

    class _MissingStrategy:
        """Inert stand-in: every attribute returns a chainable no-op so the
        ``@given(st.xxx(...).map(...)`` expressions below evaluate harmlessly
        at collection time. The whole module is skipped via pytestmark."""

        def __getattr__(self, name):
            return self

        def __call__(self, *args, **kwargs):
            return self

        def map(self, fn):
            return self

    st = _MissingStrategy()


from core.captive_portal import validate_email, validate_phone

pytestmark = pytest.mark.skipif(
    not HAVE_HYPOTHESIS,
    reason="hypothesis not installed — run `pip install -r requirements-dev.txt`",
)


# ---------------------------------------------------------------------------
# Sanity: regex stuck in place — pasting the same shape should never crash.
# ---------------------------------------------------------------------------


def test_phone_rejects_empty():
    assert validate_phone("") is False
    # ``validate_*`` is callable from request.form values, which can be
    # absent in raw lookups — must accept None and treat as invalid.
    assert validate_phone(None) is False


def test_email_rejects_empty():
    assert validate_email("") is False
    assert validate_email(None) is False


# ---------------------------------------------------------------------------
# Phone — E.164-shaped strings pass; everything else returns False.
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(st.text(min_size=1, max_size=64))
def test_phone_never_crashes(s: str) -> None:
    """The phone validator must never raise — only return True/False."""
    result = validate_phone(s)
    assert result in (True, False)


@settings(max_examples=200, deadline=None)
@given(
    # E.164 numbers: optional +, 7..15 digits.
    st.one_of(
        st.from_regex(r"\+?[0-9]{7,15}", fullmatch=True),
        st.text(alphabet="0123456789", min_size=7, max_size=15).map(lambda d: "+" + d),
    )
)
def test_phone_accepts_e164_shapes(phone: str) -> None:
    assert validate_phone(phone) is True, f"should accept {phone!r}"


@settings(max_examples=200, deadline=None)
@given(
    st.text(
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+={}[]<>?,./\\|`~",
        min_size=1,
        max_size=32,
    ).filter(lambda s: not any(ch.isdigit() for ch in s))
)
def test_phone_rejects_non_digit_input(s: str) -> None:
    # Pure-non-digit content must be rejected (the actual validate_phone
    # regex requires at least one digit-shape character).
    assert validate_phone(s) is False


# ---------------------------------------------------------------------------
# Email — sanity of the regex; never crash, reject obvious garbage.
# ---------------------------------------------------------------------------


@settings(max_examples=200, deadline=None)
@given(st.text(min_size=1, max_size=128))
def test_email_never_crashes(s: str) -> None:
    result = validate_email(s)
    assert result in (True, False)


@settings(max_examples=200, deadline=None)
@given(
    st.tuples(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789._%+-", min_size=1, max_size=20),
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=2, max_size=10),
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=2, max_size=6),
    ).map(lambda tpl: f"{tpl[0]}@{tpl[1]}.{tpl[2]}")
)
def test_email_accepts_canonical_shapes(addr: str) -> None:
    assert validate_email(addr) is True, f"should accept {addr!r}"


@settings(max_examples=200, deadline=None)
@given(st.text(alphabet="><()[]{}|\\`~!#$%^&*", min_size=1, max_size=32))
def test_email_rejects_punctuation_only_garbage(s: str) -> None:
    assert validate_email(s) is False
