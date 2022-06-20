from dataclasses import dataclass
from typing import Callable, TypeVar


_S = TypeVar('_S')
_T = TypeVar('_T')


@dataclass
class SigningInformation:
    private_key: _S
    hash_method: Callable[[bytes], _T]
    sign_method: Callable[[_S, _T], bytes]
