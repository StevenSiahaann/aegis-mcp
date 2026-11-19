"""Functional Result[T, E] monad for deterministic domain error handling."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, NoReturn, TypeVar

T = TypeVar("T")
U = TypeVar("U")
E = TypeVar("E")


@dataclass(frozen=True, slots=True)
class Ok(Generic[T]):
    """Represents a successful computation containing value T."""

    value: T

    @property
    def is_ok(self) -> bool:
        return True

    @property
    def is_err(self) -> bool:
        return False

    def unwrap(self) -> T:
        return self.value

    def unwrap_err(self) -> NoReturn:
        raise RuntimeError("Called unwrap_err() on an Ok value")

    def map(self, fn: Callable[[T], U]) -> Result[U, NoReturn]:
        return Ok(fn(self.value))


@dataclass(frozen=True, slots=True)
class Err(Generic[E]):
    """Represents a failed domain computation containing error E."""

    error: E

    @property
    def is_ok(self) -> bool:
        return False

    @property
    def is_err(self) -> bool:
        return True

    def unwrap(self) -> NoReturn:
        raise RuntimeError(f"Called unwrap() on an Err value: {self.error!r}")

    def unwrap_err(self) -> E:
        return self.error

    def map(self, fn: Callable[[NoReturn], U]) -> Result[U, E]:
        return self


Result = Ok[T] | Err[E]
