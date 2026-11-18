from typing import Any, Dict, List, Mapping, Optional, Tuple, Union, final

__version__: str
TRANSPORTS: Tuple[str, ...]

__all__ = ["Tracker", "Verdict", "decode", "read_ridf", "write_ridf", "TRANSPORTS", "__version__"]

# A radio address: "AA:BB:CC:DD:EE:FF" or 6 bytes.
_Address = Union[str, bytes]

def decode(data: bytes, transport: str = "auto") -> Dict[str, Any]:
    """Decode one Remote ID frame; raises ValueError if it is not Remote ID."""

def read_ridf(data: bytes) -> List[Dict[str, Any]]: ...
def write_ridf(
    payload: bytes,
    transport: str,
    rx_time_ns: int,
    counter: Optional[int] = None,
    rssi: Optional[int] = None,
    address: Optional[_Address] = None,
    receiver_id: int = 0,
    receiver: Optional[Tuple[float, float, float]] = None,
    utc: bool = False,
    header: bool = False,
) -> bytes: ...

@final
class Verdict:
    verdict: str
    score: float
    reasons: List[str]
    spoofer: Optional[str]
    auth: str
    address: str
    transport: str
    uas_id: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    altitude_m: Optional[float]
    frames: int
    @property
    def is_alert(self) -> bool: ...
    def to_dict(self) -> Dict[str, Any]: ...

@final
class Tracker:
    def __new__(
        cls,
        max_speed_mps: float = 100.0,
        fingerprints: bool = True,
        accept_self_certified: bool = False,
        trusted_keys: Optional[Mapping[Union[str, bytes], bytes]] = None,
        timeout_ms: int = 10000,
        use_system_clock: bool = False,
        auth_requires_clock: bool = True,
        max_transmitters: int = 4096,
    ) -> "Tracker": ...
    def ingest(
        self,
        data: bytes,
        transport: str = "auto",
        address: Optional[_Address] = None,
        now_ms: Optional[int] = None,
        unix_ms: Optional[int] = None,
        rssi: Optional[int] = None,
    ) -> Verdict: ...
    def ingest_ridf(self, data: bytes) -> List[Verdict]: ...
    def verdicts(self) -> List[Verdict]: ...
    def get(self, address: _Address) -> Verdict: ...
    def aircraft_json(
        self,
        now_ms: Optional[int] = None,
        include_operator_position: bool = False,
        include_without_position: bool = False,
    ) -> str: ...
    def expire(self, now_ms: Optional[int] = None) -> int: ...
    def __len__(self) -> int: ...
