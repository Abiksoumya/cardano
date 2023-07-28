from .types import typechecked
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    List,
    Optional,
    Type,
    TypeVar,
    Union,
    get_type_hints,
)

from decimal import Decimal
from collections import OrderedDict, UserList, defaultdict
from cbor2 import CBOREncoder, CBORSimpleValue, CBORTag, dumps, loads, undefined
from datetime import datetime
import re
from frozendict import frozendict
from frozenlist import FrozenList
from dataclasses import Field, dataclass, fields
from pprintpp import pformat
from functools import wraps
from .exception import DeserializeException




__all__ = [
    "default_encoder",
    "IndefiniteList",
    "Primitive",
    "CBORBase",
    "CBORSerializable",
    "ArrayCBORSerializable",
    "MapCBORSerializable",
    "DictCBORSerializable",
    "RawCBOR",
    "list_hook",
    "limit_primitive_type",
]
def _identity(x):
    return x



class IndefiniteList(UserList):
    def __init__(self, li: 'Primitive'):  # type: ignore
        super().__init__(li)  # type: ignore


class IndefiniteFrozenList(FrozenList, IndefiniteList):  # type: ignore
    pass


Primitive = Union[
    bytes,
    bytearray,
    str,
    int,
    float,
    Decimal,
    bool,
    None,
    tuple,
    list,
    IndefiniteList,
    dict,
    defaultdict,
    OrderedDict,
    undefined.__class__,
    datetime,
    re.Pattern,
    CBORSimpleValue,
    CBORTag,
    set,
    frozenset,
    frozendict,
    FrozenList,
    IndefiniteFrozenList,
]

CBORBase = TypeVar("CBORBase", bound="CBORSerializable")

@dataclass
class RawCBOR:
    """A wrapper class for bytes that represents a CBOR value."""

    cbor: bytes

def limit_primitive_type(*allowed_types):
    """
    A helper function to validate primitive type given to from_primitive class methods

    Not exposed to public by intention.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(cls, value: Primitive):
            if not isinstance(value, allowed_types):
                allowed_types_str = [
                    allowed_type.__name__ for allowed_type in allowed_types
                ]
                raise DeserializeException(
                    f"{allowed_types_str} typed value is required for deserialization. Got {type(value)}: {value}"
                )
            return func(cls, value)

        return wrapper

    return decorator


@typechecked
class CBORSerializable:
    """
    CBORSerializable standardizes the interfaces a class should implement in order for it to be serialized to and
    deserialized from CBOR.

    Two required interfaces to implement are :meth:`to_primitive` and :meth:`from_primitive`.
    :meth:`to_primitive` converts an object to a CBOR primitive type (see :const:`Primitive`), which could be then
    encoded by CBOR library. :meth:`from_primitive` restores an object from a CBOR primitive type.

    To convert a CBORSerializable to CBOR, use :meth:`to_cbor`.
    To restore a CBORSerializable from CBOR, use :meth:`from_cbor`.

    .. note::
        :meth:`to_primitive` needs to return a pure CBOR primitive type, meaning that the returned value and all its
        child elements have to be CBOR primitives, which could mean a good amount of work. An alternative but simpler
        approach is to implement :meth:`to_shallow_primitive` instead. `to_shallow_primitive` allows the returned object
        to be either CBOR :const:`Primitive` or a :class:`CBORSerializable`, as long as the :class:`CBORSerializable`
        does not refer to itself, which could cause infinite loops.
    """
    def to_shallow_primitive(self) -> Primitive:
        """
        Convert the instance to a CBOR primitive. If the primitive is a container, e.g. list, dict, the type of
        its elements could be either a Primitive or a CBORSerializable.

        Returns:
            :const:`Primitive`: A CBOR primitive.

        Raises:
            SerializeException: When the object could not be converted to CBOR primitive
                types.
        """
        raise NotImplementedError(
            f"'to_shallow_primitive()' is not implemented by {self.__class__}."
        )
    
    def to_primitive(self) -> Primitive:
        """Convert the instance and its elements to CBOR primitives recursively.

        Returns:
            :const:`Primitive`: A CBOR primitive.

        Raises:
            SerializeException: When the object or its elements could not be converted to
                CBOR primitive types.
        """
        result = self.to_shallow_primitive()

        def _dfs(value, freeze=False):
            if isinstance(value, CBORSerializable):
                return _dfs(value.to_primitive(), freeze)
            elif isinstance(value, (dict, OrderedDict, defaultdict)):
                _dict = type(value)()
                if hasattr(value, "default_factory"):
                    _dict.setdefault(value.default_factory)
                for k, v in value.items():
                    _dict[_dfs(k, freeze=True)] = _dfs(v, freeze)
                if freeze:
                    return frozendict(_dict)
                return _dict
            elif isinstance(value, set):
                _set = set(_dfs(v, freeze=True) for v in value)
                if freeze:
                    return frozenset(_set)
                return _set
            elif isinstance(value, tuple):
                return tuple(_dfs(v, freeze) for v in value)
            elif isinstance(value, list):
                _list = [_dfs(v, freeze) for v in value]
                if freeze:
                    fl = FrozenList(_list)
                    fl.freeze()
                    return fl
                return _list
            elif isinstance(value, IndefiniteList):
                _list = [_dfs(v, freeze) for v in value]
                if freeze:
                    fl = IndefiniteFrozenList(_list)
                    fl.freeze()
                    return fl
                return IndefiniteList(_list)
            elif isinstance(value, CBORTag):
                return CBORTag(value.tag, _dfs(value.value, freeze))
            else:
                return value

        return _dfs(result)
    
    def validate(self):
        """Validate the data stored in the current instance. Defaults to always pass.

        Raises:
            InvalidDataException: When the data is invalid.
        """
        type_hints = get_type_hints(self.__class__)

        def _check_recursive(value, type_hint):
            if type_hint is Any:
                return True
            origin = getattr(type_hint, "__origin__", None)
            if origin is None:
                if isinstance(value, CBORSerializable):
                    value.validate()
                return isinstance(value, type_hint)
            elif origin is ClassVar:
                return _check_recursive(value, type_hint.__args__[0])
            elif origin is Union:
                return any(_check_recursive(value, arg) for arg in type_hint.__args__)
            elif origin is Dict or isinstance(value, (dict, frozendict)):
                key_type, value_type = type_hint.__args__
                return all(
                    _check_recursive(k, key_type) and _check_recursive(v, value_type)
                    for k, v in value.items()
                )
            elif origin in (list, set, tuple):
                if value is None:
                    return True
                args = type_hint.__args__
                if len(args) == 1:
                    return all(_check_recursive(item, args[0]) for item in value)
                elif len(args) > 1:
                    return all(
                        _check_recursive(item, arg) for item, arg in zip(value, args)
                    )
            return True  # We don't know how to check this type

        for field_name, field_type in type_hints.items():
            field_value = getattr(self, field_name)
            if not _check_recursive(field_value, field_type):
                raise TypeError(
                    f"Field '{field_name}' should be of type {field_type}, "
                    f"got {repr(field_value)} instead."
                )
            

    def to_validated_primitive(self) -> Primitive:
        """Convert the instance and its elements to CBOR primitives recursively with data validated by :meth:`validate`
        method.

        Returns:
            :const:`Primitive`: A CBOR primitive.

        Raises:
            SerializeException: When the object or its elements could not be converted to
                CBOR primitive types.
        """
        self.validate()
        return self.to_primitive()
    
    @classmethod
    def from_primitive(cls: Type[CBORBase], value: Any) -> CBORBase:
        """Turn a CBOR primitive to its original class type.

        Args:
            cls (CBORBase): The original class type.
            value (:const:`Primitive`): A CBOR primitive.

        Returns:
            CBORBase: A CBOR serializable object.

        Raises:
            DeserializeException: When the object could not be restored from primitives.
        """
        raise NotImplementedError(
            f"'from_primitive()' is not implemented by {cls.__name__}."
        )
    
    def to_cbor(self) -> bytes:
        """Encode a Python object into CBOR bytes.

        Returns:
            bytes: Python object encoded in cbor bytes.

        Examples:
            >>> class Test(CBORSerializable):
            ...     def __init__(self, number1, number2):
            ...         self.number1 = number1
            ...         self.number2 = number2
            ...
            ...     def to_primitive(value):
            ...         return [value.number1, value.number2]
            ...
            ...     @classmethod
            ...     def from_primitive(cls, value):
            ...         return cls(value[0], value[1])
            ...
            ...     def __repr__(self):
            ...         return f"Test({self.number1}, {self.number2})"
            >>> a = Test(1, 2)
            >>> a.to_cbor().hex()
            '820102'
        """
        return dumps(self, default=default_encoder)
    
    def to_cbor_hex(self) -> str:
        """Encode a Python object into CBOR hex.

        Returns:
            str: Python object encoded in cbor hex string.
        """
        return self.to_cbor().hex()
    
    @classmethod
    def from_cbor(cls, payload: Union[str, bytes]) -> 'CBORSerializable':
        """Restore a CBORSerializable object from a CBOR.

        Args:
            payload (Union[str, bytes]): CBOR bytes or hex string to restore from.

        Returns:
            CBORSerializable: Restored CBORSerializable object.

        Examples:

            Basic use case:

            >>> class Test(CBORSerializable):
            ...     def __init__(self, number1, number2):
            ...         self.number1 = number1
            ...         self.number2 = number2
            ...
            ...     def to_primitive(value):
            ...         return [value.number1, value.number2]
            ...
            ...     @classmethod
            ...     def from_primitive(cls, value):
            ...         return cls(value[0], value[1])
            ...
            ...     def __repr__(self):
            ...         return f"Test({self.number1}, {self.number2})"
            >>> a = Test(1, 2)
            >>> cbor_hex = a.to_cbor_hex()
            >>> print(Test.from_cbor(cbor_hex))
            Test(1, 2)

            For a CBORSerializable that has CBORSerializables as attributes, we will need to pass
            each child value to the :meth:`from_primitive` method of its corresponding CBORSerializable. Example:

            >>> class TestParent(CBORSerializable):
            ...     def __init__(self, number1, test):
            ...         self.number1 = number1
            ...         self.test = test
            ...
            ...     def to_shallow_primitive(value): # Implementing `to_shallow_primitive` simplifies the work.
            ...         return [value.number1, value.test]
            ...
            ...     @classmethod
            ...     def from_primitive(cls, value):
            ...         test = Test.from_primitive(value[1]) # Restore test by passing `value[1]` to
            ...                                              # `Test.from_primitive`
            ...         return cls(value[0], test)
            ...
            ...     def __repr__(self):
            ...         return f"TestParent({self.number1}, {self.test})"
            >>> a = Test(1, 2)
            >>> b = TestParent(3, a)
            >>> b
            TestParent(3, Test(1, 2))
            >>> cbor_hex = b.to_cbor_hex()
            >>> cbor_hex
            '8203820102'
            >>> print(TestParent.from_cbor(cbor_hex))
            TestParent(3, Test(1, 2))

        """
        if type(payload) == str:
            payload = bytes.fromhex(payload)
        value = loads(payload)
        return cls.from_primitive(value)

    def __repr__(self):
        return pformat(vars(self), indent=2)
    


    

def default_encoder(
    encoder: CBOREncoder, value: Union[CBORSerializable, IndefiniteList]
):
    """A fallback function that encodes CBORSerializable to CBOR"""
    assert isinstance(
        value,
        (
            CBORSerializable,
            IndefiniteList,
            RawCBOR,
            FrozenList,
            IndefiniteFrozenList,
            frozendict,
        ),
    ), (
        f"Type of input value is not CBORSerializable, " f"got {type(value)} instead."
    )
    if isinstance(value, (IndefiniteList, IndefiniteFrozenList)):
        # Currently, cbor2 doesn't support indefinite list, therefore we need special
        # handling here to explicitly write header (b'\x9f'), each body item, and footer (b'\xff') to
        # the output bytestring.
        encoder.write(b"\x9f")
        for item in value:
            encoder.encode(item)
        encoder.write(b"\xff")
    elif isinstance(value, RawCBOR):
        encoder.write(value.cbor)
    elif isinstance(value, FrozenList):
        encoder.encode(list(value))
    elif isinstance(value, frozendict):
        encoder.encode(dict(value))
    else:
        encoder.encode(value.to_validated_primitive())