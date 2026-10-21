"""Implementation of EphemeralValueStore.

This class provides an in-memory store of temporary string values,
identified by opaque references, with strict limits on value size,
total size and count. It is not serializable, copyable or pickleable
and does not expose any internal structure.

"""

from __future__ import annotations

_MISSING_REF_ERR = "Value reference not found."
_DUPLICATE_REF_ERR = "Duplicate value_ref"
_CLOSED_ERR = "EphemeralValueStore is closed"
_CLASSIFICATION_ERR = "Invalid classification"
_CLASSIFICATIONS = frozenset({"non_persistable", "sensitive"})
_MAX_STRUCTURAL_INTEGER = (1 << 63) - 1


class EphemeralValueStore:
    """Store for temporary values used by the future browser.

    Parameters:
        scope_id: Identifier of the scope.
        max_values: Maximum number of values that can be stored.
        max_value_utf8_bytes: Maximum UTF‑8 byte size of a single value.
        max_total_utf8_bytes: Maximum total UTF‑8 byte size of all values.
    """

    @staticmethod
    def _plain_string(value, field_name: str) -> str:
        if not issubclass(type(value), str):
            raise ValueError(f"{field_name} must be a string")
        return str.__str__(value)

    __slots__ = (
        "_scope_id",
        "_max_values",
        "_max_value_utf8_bytes",
        "_max_total_utf8_bytes",
        "_data",
        "_total_utf8_bytes",
        "_closed",
    )

    def __init__(
        self,
        scope_id: str,
        *,
        max_values: int,
        max_value_utf8_bytes: int,
        max_total_utf8_bytes: int,
    ) -> None:
        # Validate scope_id
        plain_scope_id = self._plain_string(scope_id, "scope_id")
        scope_id = plain_scope_id.strip()
        if not 1 <= len(scope_id) <= 128:
            raise ValueError("scope_id cannot be empty or exceed 128 characters")
        # Validate limits
        for name, value in (
            ("max_values", max_values),
            ("max_value_utf8_bytes", max_value_utf8_bytes),
            ("max_total_utf8_bytes", max_total_utf8_bytes),
        ):
            if type(value) is not int:
                raise TypeError(f"{name} must be an int")
            if not 1 <= value <= _MAX_STRUCTURAL_INTEGER:
                raise ValueError(f"{name} must be >= 1 and <= 2**63-1")
        self._scope_id: str = scope_id
        self._max_values = max_values
        self._max_value_utf8_bytes = max_value_utf8_bytes
        self._max_total_utf8_bytes = max_total_utf8_bytes

        self._data: dict[str, str] = {}
        self._total_utf8_bytes: int = 0
        self._closed: bool = False

    # Properties
    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def count(self) -> int:
        return len(self._data)

    @property
    def total_utf8_bytes(self) -> int:
        return self._total_utf8_bytes

    # Internal helpers
    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError(_CLOSED_ERR)

    def _normalize_ref(self, value_ref: str) -> str:
        plain_ref = self._plain_string(value_ref, "value_ref")
        normalized = plain_ref.strip()
        if not 1 <= len(normalized) <= 128:
            raise ValueError("value_ref must be non-empty and <= 128 characters")
        return normalized

    # API methods
    def store(
        self,
        value_ref: str,
        value: str,
        *,
        classification: str,
    ) -> None:
        self._ensure_open()
        classification = self._plain_string(classification, "classification")
        if classification not in _CLASSIFICATIONS:
            raise ValueError(_CLASSIFICATION_ERR)

        value_ref = self._normalize_ref(value_ref)
        if value_ref in self._data:
            raise KeyError(_DUPLICATE_REF_ERR)

        value = self._plain_string(value, "value")
        try:
            size = len(value.encode("utf-8"))
        except UnicodeEncodeError:
            raise ValueError("value must be valid UTF-8 text") from None
        if size > self._max_value_utf8_bytes:
            raise ValueError("Value size exceeds max_value_utf8_bytes")
        if self.count + 1 > self._max_values:
            raise ValueError("Exceeds max_values limit")
        if self.total_utf8_bytes + size > self._max_total_utf8_bytes:
            raise ValueError("Exceeds max_total_utf8_bytes limit")

        # Store
        self._data[value_ref] = value
        self._total_utf8_bytes += size

    def resolve(self, value_ref: str) -> str:
        self._ensure_open()
        value_ref = self._normalize_ref(value_ref)
        try:
            return self._data[value_ref]
        except KeyError:
            raise KeyError(_MISSING_REF_ERR) from None

    def discard(self, value_ref: str) -> None:
        self._ensure_open()
        value_ref = self._normalize_ref(value_ref)
        try:
            value = self._data.pop(value_ref)
        except KeyError:
            raise KeyError(_MISSING_REF_ERR) from None
        self._total_utf8_bytes -= len(value.encode("utf-8"))

    def close(self) -> None:
        if not self._closed:
            self._data.clear()
            self._total_utf8_bytes = 0
            self._closed = True

    # Context manager
    def __enter__(self) -> EphemeralValueStore:
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False  # Do not suppress exceptions

    # Representation
    def __repr__(self) -> str:
        state = "closed" if self._closed else "open"
        return f"EphemeralValueStore({state})"

    # Disable serialization / copying
    def __reduce__(self):
        raise TypeError("EphemeralValueStore cannot be pickled")

    def __copy__(self):
        raise TypeError("EphemeralValueStore cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("EphemeralValueStore cannot be deep-copied")

    # Prevent dict-like iteration
    def __iter__(self):
        raise TypeError("EphemeralValueStore is not iterable")
