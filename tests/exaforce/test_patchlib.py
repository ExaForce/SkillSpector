from types import ModuleType

import pytest
from pydantic import BaseModel

from skillspector.exaforce._patchlib import (
    PatchDriftError,
    intercept_method,
    intercept_module_callable,
    pop_field_validator,
    remove_model_fields,
    replace_module_str,
)


def test_remove_model_fields_removes_then_rebuild_drops_key():
    class M(BaseModel):
        a: str
        b: str = ""

    remove_model_fields(M, ["b"])
    M.model_rebuild(force=True)
    assert "b" not in M.model_json_schema()["properties"]
    assert "a" in M.model_json_schema()["properties"]


def test_remove_model_fields_raises_on_missing_field():
    class M(BaseModel):
        a: str

    with pytest.raises(PatchDriftError):
        remove_model_fields(M, ["nope"])


def test_pop_field_validator_is_noop_when_absent():
    class M(BaseModel):
        a: str

    pop_field_validator(M, "nonexistent")  # must not raise


def test_replace_module_str_replaces_substring():
    mod = ModuleType("dummy")
    mod.P = "hello world"
    replace_module_str(mod, "P", "world", "there")
    assert mod.P == "hello there"


def test_replace_module_str_raises_on_missing_substring():
    mod = ModuleType("dummy")
    mod.P = "hello world"
    with pytest.raises(PatchDriftError):
        replace_module_str(mod, "P", "absent", "x")


def _mod_with(fn):
    mod = ModuleType("dummy")
    mod.f = fn
    return mod


def test_intercept_sees_args_and_can_replace_result():
    mod = _mod_with(lambda a, b=0: a + b)
    seen = {}

    def interceptor(original, args, kwargs):
        seen["args"], seen["kwargs"] = args, kwargs
        return original(*args, **kwargs) * 10

    intercept_module_callable(mod, "f", interceptor, expected_params=("a", "b"))
    assert mod.f(1, b=2) == 30
    assert seen == {"args": (1,), "kwargs": {"b": 2}}


def test_intercept_is_idempotent():
    mod = _mod_with(lambda a: a)
    calls = []

    def interceptor(original, args, kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    intercept_module_callable(mod, "f", interceptor)
    first = mod.f
    intercept_module_callable(mod, "f", interceptor)
    assert mod.f is first
    mod.f(1)
    assert calls == [1]


def test_intercept_drift_missing_param():
    mod = _mod_with(lambda a: a)
    with pytest.raises(PatchDriftError):
        intercept_module_callable(mod, "f", lambda o, a, k: None, expected_params=("zzz",))
    with pytest.raises(PatchDriftError):
        intercept_module_callable(mod, "missing", lambda o, a, k: None)


def _cls():
    class C:
        def f(self, a, b=0):
            return (self, a + b)

    return C


def test_intercept_method_sees_self_args_and_can_replace_result():
    klass = _cls()
    seen = {}

    def interceptor(original, self, args, kwargs):
        seen["self"], seen["args"], seen["kwargs"] = self, args, kwargs
        return original(self, *args, **kwargs)[1] * 10

    intercept_method(klass, "f", interceptor, expected_params=("a", "b"))
    obj = klass()
    assert obj.f(1, b=2) == 30
    assert seen == {"self": obj, "args": (1,), "kwargs": {"b": 2}}


def test_intercept_method_is_idempotent():
    klass = _cls()
    calls = []

    def interceptor(original, self, args, kwargs):
        calls.append(1)
        return original(self, *args, **kwargs)

    intercept_method(klass, "f", interceptor)
    first = klass.f
    intercept_method(klass, "f", interceptor)
    assert klass.f is first
    klass().f(1)
    assert calls == [1]


def test_intercept_method_drift_missing_param():
    klass = _cls()
    with pytest.raises(PatchDriftError):
        intercept_method(klass, "f", lambda o, s, a, k: None, expected_params=("zzz",))
    with pytest.raises(PatchDriftError):
        intercept_method(klass, "missing", lambda o, s, a, k: None)
