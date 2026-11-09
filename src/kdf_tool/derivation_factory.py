from dataclasses import dataclass

@dataclass(frozen=True)
class HKDFDerivationRequest:
    id: str
    length: int
    info: bytes

    def __post_init__(self):
        if not isinstance(self.id, str):
            raise TypeError("id must be a string")
        if len(self.id) == 0:
            raise ValueError("id cannot be empty")
        if self.id != self.id.strip():
            raise ValueError("id cannot contains spaces or tabulations")
        if isinstance(self.length, bool) or not isinstance(self.length, int):
            raise TypeError("length must be an integer")
        if self.length < 1:
            raise ValueError("length must be positive")
        if not isinstance(self.info, bytes):
            raise TypeError("info must be bytes")