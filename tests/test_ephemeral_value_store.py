"""Contract tests for the in-memory, non-serializable ephemeral value store."""

import copy
import http.client
import io
import os
import pickle
import socket
import subprocess
import unittest
import urllib.request
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from jarvis.core.ephemeral_value_store import EphemeralValueStore


LIMIT_NAMES = ("max_values", "max_value_utf8_bytes", "max_total_utf8_bytes")


def new_store(scope_id="scope", **overrides):
    limits = {
        "max_values": 4,
        "max_value_utf8_bytes": 64,
        "max_total_utf8_bytes": 128,
    }
    limits.update(overrides)
    return EphemeralValueStore(scope_id, **limits)


class IntSubclass(int):
    pass


class HostileString(str):
    def __new__(cls, value):
        instance = str.__new__(cls, value)
        instance.state = []
        return instance

    def unexpected(self, *args, **kwargs):
        raise AssertionError("hostile string callback executed")

    strip = __str__ = __len__ = __iter__ = __eq__ = __hash__ = encode = unexpected


class HostileNonString:
    @property
    def __class__(self):
        raise AssertionError("hostile type callback executed")

    def unexpected(self, *args, **kwargs):
        raise AssertionError("non-string callback executed")

    __str__ = __iter__ = __eq__ = __hash__ = __call__ = unexpected


class TestEphemeralValueStore(unittest.TestCase):
    @staticmethod
    def snapshot(store):
        return store.closed, store.count, store.total_utf8_bytes, store._data.copy()

    def test_constructor_and_property_types(self):
        store = new_store()
        self.assertIs(store.closed, False)
        self.assertEqual(store.count, 0)
        self.assertEqual(store.total_utf8_bytes, 0)
        self.assertIs(type(store.count), int)
        self.assertIs(type(store.total_utf8_bytes), int)

    def test_scope_is_stripped_and_accepts_128_characters(self):
        for source, expected in (
            (" \t scope local:ñ/1 \n ", "scope local:ñ/1"),
            ("x" * 128, "x" * 128),
            (" " + "x" * 128 + " ", "x" * 128),
        ):
            with self.subTest(source=source):
                store = new_store(source)
                self.assertEqual(store._scope_id, expected)
                self.assertIs(type(store._scope_id), str)

    def test_scope_empty_whitespace_and_over_128_are_rejected(self):
        for scope in ("", " \t\n", "x" * 129):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                new_store(scope)

    def test_limit_boundaries_for_each_limit(self):
        for name in LIMIT_NAMES:
            for value in (1, (1 << 63) - 1):
                with self.subTest(limit=name, value=value):
                    store = new_store(**{name: value})
                    self.assertEqual(self.snapshot(store), (False, 0, 0, {}))
        store = new_store(**dict.fromkeys(LIMIT_NAMES, 1))
        store.store("ref", "x", classification="sensitive")
        self.assertEqual((store.count, store.total_utf8_bytes), (1, 1))

    def test_every_limit_rejects_bool_and_non_exact_int(self):
        for name in LIMIT_NAMES:
            for value in (True, False, 1.0, "1", None, IntSubclass(1)):
                with self.subTest(limit=name, value=value), self.assertRaises(TypeError):
                    new_store(**{name: value})

    def test_every_limit_rejects_out_of_range_int(self):
        for name in LIMIT_NAMES:
            for value in (0, -1, 1 << 63):
                with self.subTest(limit=name, value=value), self.assertRaises(ValueError):
                    new_store(**{name: value})

    def test_hostile_strings_are_detached_without_callbacks_or_retained_state(self):
        for classification_text in ("non_persistable", "sensitive"):
            with self.subTest(classification=classification_text):
                scope = HostileString(" scope ")
                ref = HostileString(" ref ")
                value = HostileString("  ñ😀 \t")
                classification = HostileString(classification_text)
                store = new_store(scope)
                self.assertIsNone(store.store(ref, value, classification=classification))
                for hostile in (scope, ref, value, classification):
                    hostile.state.append("changed mutable state")
                result = store.resolve("ref")
                self.assertIs(type(result), str)
                self.assertEqual(result, "  ñ😀 \t")
                self.assertEqual(store._scope_id, "scope")
                self.assertIs(type(store._scope_id), str)
                self.assertIs(type(next(iter(store._data))), str)
                self.assertEqual((store.count, store.total_utf8_bytes), (1, 10))
                self.assertEqual(store.resolve(ref), "  ñ😀 \t")
                self.assertIsNone(store.discard(ref))
                self.assertEqual((store.count, store.total_utf8_bytes), (0, 0))

    def test_hostile_non_strings_raise_value_error_without_callbacks(self):
        hostile = HostileNonString()
        with self.assertRaises(ValueError) as caught:
            new_store(hostile)
        self.assertEqual(caught.exception.args, ("scope_id must be a string",))
        store = new_store()
        store.store("known", "original", classification="sensitive")
        before = self.snapshot(store)
        defaults = {"value_ref": "new", "value": "text", "classification": "sensitive"}
        for field in defaults:
            with self.subTest(field=field):
                arguments = defaults.copy()
                arguments[field] = hostile
                with self.assertRaises(ValueError) as caught:
                    store.store(**arguments)
                self.assertEqual(caught.exception.args, (f"{field} must be a string",))
                self.assertEqual(self.snapshot(store), before)
        for method in (store.resolve, store.discard):
            with self.subTest(method=method.__name__):
                with self.assertRaises(ValueError) as caught:
                    method(hostile)
                self.assertEqual(caught.exception.args, ("value_ref must be a string",))
                self.assertEqual(self.snapshot(store), before)

    def test_other_non_string_inputs_are_rejected_without_state_changes(self):
        for value in (None, 1, True, b"text", [], {}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    new_store(value)
                store = new_store()
                store.store("known", "original", classification="sensitive")
                before = self.snapshot(store)
                for field in ("value_ref", "value", "classification"):
                    arguments = {"value_ref": "new", "value": "text", "classification": "sensitive"}
                    arguments[field] = value
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        store.store(**arguments)
                    self.assertEqual(self.snapshot(store), before)

    def test_ref_is_stripped_in_store_resolve_and_discard_and_accepts_128(self):
        store = new_store()
        ref = "x" * 128
        store.store(" \t" + ref + " ", "text", classification="sensitive")
        self.assertEqual(store.resolve(" " + ref + "\n"), "text")
        store.discard("\t" + ref + " ")
        self.assertEqual(self.snapshot(store), (False, 0, 0, {}))

    def test_invalid_refs_in_all_operations_preserve_state(self):
        store = new_store()
        store.store("known", "original", classification="sensitive")
        before = self.snapshot(store)
        operations = (
            ("store", lambda ref: store.store(ref, "text", classification="sensitive")),
            ("resolve", store.resolve),
            ("discard", store.discard),
        )
        for ref in ("", " \t\n", "x" * 129):
            for label, operation in operations:
                with self.subTest(operation=label, ref=ref), self.assertRaises(ValueError):
                    operation(ref)
                self.assertEqual(self.snapshot(store), before)

    def test_both_classifications_are_accepted(self):
        store = new_store()
        for classification in ("non_persistable", "sensitive"):
            store.store(classification, "text", classification=classification)
            self.assertEqual(store.resolve(classification), "text")
        self.assertEqual((store.count, store.total_utf8_bytes), (2, 8))

    def test_classification_is_closed_without_stripping_or_lowercasing(self):
        store = new_store()
        store.store("known", "original", classification="sensitive")
        before = self.snapshot(store)
        for classification in (
            "", "other", "SENSITIVE", "NON_PERSISTABLE", " sensitive", "sensitive ",
            " non_persistable ", "sensitive\n", "CLASSIFICATION_SECRET",
        ):
            with self.subTest(classification=classification):
                with self.assertRaises(ValueError) as caught:
                    store.store("new", "text", classification=classification)
                self.assertEqual(caught.exception.args, ("Invalid classification",))
                self.assertEqual(self.snapshot(store), before)

    def test_empty_whitespace_unicode_emoji_and_controls_are_preserved(self):
        for value, size in (
            ("", 0), ("  x \t\n", 6), ("ñé中", 7), ("😀", 4), ("\x00x", 2), ("e\u0301", 3),
        ):
            with self.subTest(value=value):
                store = new_store()
                store.store("ref", value, classification="non_persistable")
                result = store.resolve("ref")
                self.assertIs(type(result), str)
                self.assertEqual(result, value)
                self.assertEqual((store.count, store.total_utf8_bytes), (1, size))

    def test_invalid_utf8_raises_exact_safe_error_and_preserves_state(self):
        for value in ("\ud800", "\udfff", "VALUE_SECRET\ud800", HostileString("\ud800")):
            with self.subTest(value_type=type(value).__name__):
                store = new_store()
                store.store("known", "original", classification="sensitive")
                before = self.snapshot(store)
                with self.assertRaises(ValueError) as caught:
                    store.store("new", value, classification="non_persistable")
                self.assertEqual(caught.exception.args, ("value must be valid UTF-8 text",))
                self.assertIsNone(caught.exception.__cause__)
                self.assertTrue(caught.exception.__suppress_context__)
                self.assertEqual(self.snapshot(store), before)
                store.store("new", "valid", classification="sensitive")
                self.assertEqual(store.resolve("new"), "valid")

    def test_max_values_exact_capacity_and_one_more_is_atomic(self):
        store = new_store(max_values=2)
        store.store("first", "a", classification="sensitive")
        store.store("second", "b", classification="non_persistable")
        self.assertEqual((store.count, store.total_utf8_bytes), (2, 2))
        before = self.snapshot(store)
        with self.assertRaises(ValueError) as caught:
            store.store("third", "", classification="sensitive")
        self.assertEqual(caught.exception.args, ("Exceeds max_values limit",))
        self.assertEqual(self.snapshot(store), before)

    def test_per_value_utf8_exact_four_bytes_and_five_bytes_is_atomic(self):
        store = new_store(max_value_utf8_bytes=4)
        store.store("first", "😀", classification="non_persistable")
        self.assertEqual(store.resolve("first"), "😀")
        self.assertEqual((store.count, store.total_utf8_bytes), (1, 4))
        before = self.snapshot(store)
        with self.assertRaises(ValueError) as caught:
            store.store("second", "😀a", classification="sensitive")
        self.assertEqual(caught.exception.args, ("Value size exceeds max_value_utf8_bytes",))
        self.assertEqual(self.snapshot(store), before)

    def test_total_utf8_exact_five_bytes_and_one_more_is_atomic(self):
        store = new_store(max_total_utf8_bytes=5)
        store.store("first", "abc", classification="non_persistable")
        store.store("second", "de", classification="sensitive")
        self.assertEqual((store.count, store.total_utf8_bytes), (2, 5))
        before = self.snapshot(store)
        with self.assertRaises(ValueError) as caught:
            store.store("third", "a", classification="sensitive")
        self.assertEqual(caught.exception.args, ("Exceeds max_total_utf8_bytes limit",))
        self.assertEqual(self.snapshot(store), before)
        store.store("third", "", classification="sensitive")
        self.assertEqual((store.count, store.total_utf8_bytes), (3, 5))

    def test_duplicate_ref_never_overwrites_and_uses_constant_error(self):
        store = new_store()
        refs = ("REFERENCE_SECRET_A", "REFERENCE_SECRET_B")
        for ref in refs:
            store.store(ref, "original", classification="sensitive")
        before = self.snapshot(store)
        for ref in refs:
            with self.subTest(ref=ref):
                with self.assertRaises(KeyError) as caught:
                    store.store(" " + ref + " ", "REPLACEMENT_SECRET", classification="non_persistable")
                self.assertEqual(caught.exception.args, ("Duplicate value_ref",))
                self.assertNotIn(ref, str(caught.exception))
                self.assertNotIn("REPLACEMENT_SECRET", str(caught.exception))
                self.assertEqual(self.snapshot(store), before)
                self.assertEqual(store.resolve(ref), "original")

    def test_missing_ref_errors_are_constant_without_state_changes(self):
        store = new_store()
        store.store("known", "original", classification="sensitive")
        before = self.snapshot(store)
        for ref in ("MISSING_REFERENCE_SECRET_A", "MISSING_REFERENCE_SECRET_B"):
            for operation in (store.resolve, store.discard):
                with self.subTest(operation=operation.__name__, ref=ref):
                    with self.assertRaises(KeyError) as caught:
                        operation(ref)
                    self.assertEqual(caught.exception.args, ("Value reference not found.",))
                    self.assertNotIn(ref, str(caught.exception))
                    self.assertIsNone(caught.exception.__cause__)
                    self.assertTrue(caught.exception.__suppress_context__)
                    self.assertEqual(self.snapshot(store), before)

    def test_discard_reduces_bytes_and_ref_can_be_reused(self):
        store = new_store(max_values=2, max_total_utf8_bytes=7)
        store.store("emoji", "😀", classification="sensitive")
        store.store("ascii", "abc", classification="non_persistable")
        self.assertEqual((store.count, store.total_utf8_bytes), (2, 7))
        self.assertIsNone(store.discard("emoji"))
        self.assertEqual((store.count, store.total_utf8_bytes), (1, 3))
        self.assertEqual(store.resolve("ascii"), "abc")
        with self.assertRaises(KeyError):
            store.resolve("emoji")
        before = self.snapshot(store)
        with self.assertRaises(KeyError):
            store.discard("emoji")
        self.assertEqual(self.snapshot(store), before)
        store.store("emoji", "de", classification="sensitive")
        self.assertEqual(store.resolve("emoji"), "de")
        self.assertEqual((store.count, store.total_utf8_bytes), (2, 5))

    def test_close_clears_data_bytes_and_is_idempotent(self):
        store = new_store()
        store.store("first", "😀", classification="sensitive")
        store.store("second", "text", classification="non_persistable")
        self.assertIsNone(store.close())
        self.assertEqual(self.snapshot(store), (True, 0, 0, {}))
        self.assertIs(store.closed, True)
        self.assertIsNone(store.close())
        self.assertEqual(self.snapshot(store), (True, 0, 0, {}))

    def test_operations_and_enter_after_close_use_same_constant_error(self):
        store = new_store()
        store.close()
        hostile = HostileNonString()
        operations = (
            lambda: store.store("ref", "text", classification="sensitive"),
            lambda: store.resolve("ref"),
            lambda: store.discard("ref"),
            store.__enter__,
            lambda: store.store(hostile, hostile, classification=hostile),
            lambda: store.resolve(hostile),
            lambda: store.discard(hostile),
        )
        for index, operation in enumerate(operations):
            with self.subTest(operation=index):
                with self.assertRaises(RuntimeError) as caught:
                    operation()
                self.assertEqual(caught.exception.args, ("EphemeralValueStore is closed",))
                self.assertEqual(self.snapshot(store), (True, 0, 0, {}))

    def test_normal_context_returns_self_and_closes(self):
        store = new_store()
        with store as entered:
            self.assertIs(entered, store)
            store.store("ref", "text", classification="sensitive")
            self.assertFalse(store.closed)
        self.assertEqual(self.snapshot(store), (True, 0, 0, {}))

    def test_exceptional_context_closes_without_suppressing_original_exception(self):
        store = new_store()
        original = LookupError("original error")
        with self.assertRaises(LookupError) as caught:
            with store:
                store.store("ref", "text", classification="sensitive")
                raise original
        self.assertIs(caught.exception, original)
        self.assertEqual(self.snapshot(store), (True, 0, 0, {}))

    def test_exit_calls_close_and_returns_exact_false(self):
        store = new_store()
        with patch.object(EphemeralValueStore, "close", autospec=True, wraps=None) as close:
            self.assertIs(store.__exit__(None, None, None), False)
            close.assert_called_once_with(store)

    def test_repr_is_exact_and_never_exposes_scope_ref_value_or_count(self):
        store = new_store("SCOPE_SECRET")
        self.assertEqual(repr(store), "EphemeralValueStore(open)")
        store.store("REFERENCE_SECRET", "VALUE_SECRET", classification="sensitive")
        self.assertEqual(repr(store), "EphemeralValueStore(open)")
        for secret in ("SCOPE_SECRET", "REFERENCE_SECRET", "VALUE_SECRET", "count"):
            self.assertNotIn(secret, repr(store))
        store.close()
        self.assertEqual(repr(store), "EphemeralValueStore(closed)")

    def test_copy_deepcopy_and_pickle_are_rejected_open_and_closed(self):
        for closed in (False, True):
            store = new_store()
            store.store("ref", "secret", classification="sensitive")
            if closed:
                store.close()
            before = self.snapshot(store)
            operations = (
                ("copy", copy.copy), ("deepcopy", copy.deepcopy), ("pickle", pickle.dumps),
                ("pickle_zero", lambda value: pickle.dumps(value, protocol=0)),
                ("pickle_highest", lambda value: pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)),
            )
            for label, operation in operations:
                with self.subTest(closed=closed, operation=label), self.assertRaises(TypeError):
                    operation(store)
                self.assertEqual(self.snapshot(store), before)

    def test_no_dict_serializers_or_mapping_api(self):
        store = new_store()
        for name in ("__dict__", "to_dict", "to_mapping", "to_json", "serialize", "save", "load", "items", "keys", "values"):
            with self.subTest(attribute=name):
                self.assertFalse(hasattr(store, name))
        with self.assertRaises(AttributeError):
            store.extra = "new"
        with self.assertRaises(TypeError):
            iter(store)

    def test_properties_are_read_only(self):
        store = new_store()
        for name in ("closed", "count", "total_utf8_bytes"):
            with self.subTest(property=name), self.assertRaises(AttributeError):
                setattr(store, name, 1)
        self.assertEqual(self.snapshot(store), (False, 0, 0, {}))

    def test_store_lifecycle_does_not_access_io_or_launch_processes(self):
        targets = (
            (socket, "getaddrinfo"), (socket, "gethostbyname"), (socket, "gethostbyname_ex"),
            (socket, "socket"), (socket, "create_connection"), (urllib.request, "urlopen"),
            (http.client.HTTPConnection, "connect"), (http.client.HTTPSConnection, "connect"),
            (io, "open"), (os, "open"), (os, "stat"), (Path, "read_text"), (Path, "write_text"),
            (subprocess, "run"), (subprocess, "Popen"),
        )
        with ExitStack() as stack:
            guards = [
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError("I/O executed")))
                for owner, name in targets
            ]
            guards.append(stack.enter_context(patch("builtins.open", side_effect=AssertionError("I/O executed"))))
            with new_store() as store:
                store.store("ref", "😀", classification="sensitive")
                self.assertEqual(store.resolve("ref"), "😀")
                store.discard("ref")
            store.close()
            self.assertEqual(self.snapshot(store), (True, 0, 0, {}))
            for guard in guards:
                guard.assert_not_called()


if __name__ == "__main__":
    unittest.main()
