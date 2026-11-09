
from dataclasses import dataclass
from types import MappingProxyType
from typing import Optional

from argon2.low_level import ARGON2_VERSION


# PREDEFINED PROFILES
PROFILES_ATTRIBUTES = MappingProxyType({
    "BASIC": MappingProxyType({
        "time_cost": 3,
        "memory_cost": 262144,
        "parallelism": 4
    }),
    "HIGH": MappingProxyType({
        "time_cost": 3,
        "memory_cost": 524288,
        "parallelism": 4
    }),
    "MAX": MappingProxyType({
        "time_cost": 3,
        "memory_cost": 1048576,
        "parallelism": 4
    })
})

PROFILES = tuple(PROFILES_ATTRIBUTES.keys())

# OWN LIMITS FOR THE CONFIGURATION
MIN_TIME_COST = 1
MAX_TIME_COST = 10

MIN_MEMORY_COST = 8
MAX_MEMORY_COST = 2097152  # 2 GiB in KiB

MIN_PARALLELISM = 1
MAX_PARALLELISM = 16

MIN_HASH_LEN = 4
MAX_HASH_LEN = 1024         # in bytes

# AUX FUNCTIONS
def validate_integer(name: str, value: int, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")

    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")


def validate_parameters(time_cost: int, memory_cost: int, parallelism: int, hash_len: int) -> None:
    validate_integer("time_cost", time_cost,MIN_TIME_COST, MAX_TIME_COST)
    validate_integer("memory_cost", memory_cost, MIN_MEMORY_COST, MAX_MEMORY_COST)
    validate_integer("parallelism", parallelism,MIN_PARALLELISM, MAX_PARALLELISM)
    validate_integer("hash_len", hash_len, MIN_HASH_LEN, MAX_HASH_LEN)

    if memory_cost < 8 * parallelism:
        raise ValueError("memory_cost must be at least 8 * parallelism")

# CONFIGURATION CLASS
@dataclass(frozen=True)
class Argon2Config:
    profile: str
    time_cost: int
    memory_cost: int
    parallelism: int
    hash_len: int
    version: int

    def __post_init__(self) -> None:

        if not isinstance(self.profile, str):
            raise TypeError("profile must be a string")

        if self.profile not in (*PROFILES, "CUSTOM"):
            raise ValueError("Unknown profile")

        validate_parameters(self.time_cost,self.memory_cost,
                            self.parallelism,self.hash_len)

        if isinstance(self.version, bool) or not isinstance(
            self.version, int
        ):
            raise TypeError("version must be an integer")

        if self.version != ARGON2_VERSION:
            raise ValueError("Unsupported Argon2 version")

        # CHECK A PREDEFINED PROFILE STILL HAVE THE PROPPER VALUES
        if self.profile != "CUSTOM":
            expected = PROFILES_ATTRIBUTES[self.profile]

            if (self.time_cost != expected["time_cost"]
                or self.memory_cost != expected["memory_cost"]
                or self.parallelism != expected["parallelism"]):
                raise ValueError(
                    "Parameters do not match the selected profile"
                )

# BUILDER CLASS FOR ARGON2CONFIG
class Argon2ConfigBuilder:
    
    def __init__(self) -> None:
        self.profile: Optional[str] = None
        self.time_cost: Optional[int] = None
        self.memory_cost: Optional[int] = None
        self.parallelism: Optional[int] = None
        self.hash_len: int = 32

    def set_profile(self, profile: str) -> "Argon2ConfigBuilder":
        if not isinstance(profile, str):
            raise TypeError("profile must be a string")
        if profile not in PROFILES:
            raise ValueError("Unknown profile")
        self.profile = profile
        profile_data = PROFILES_ATTRIBUTES[profile]
        self.time_cost = profile_data["time_cost"]
        self.memory_cost = profile_data["memory_cost"]
        self.parallelism = profile_data["parallelism"]
        return self

    def set_time_cost(self, time_cost: int) -> "Argon2ConfigBuilder":
        validate_integer("time_cost", time_cost, MIN_TIME_COST, MAX_TIME_COST)
        self.time_cost = time_cost
        self.profile = "CUSTOM"
        return self

    def set_memory_cost(self, memory_cost: int) -> "Argon2ConfigBuilder":
        validate_integer("memory_cost", memory_cost, MIN_MEMORY_COST, MAX_MEMORY_COST)
        self.memory_cost = memory_cost
        self.profile = "CUSTOM"
        return self

    def set_parallelism(self, parallelism: int) -> "Argon2ConfigBuilder":
        validate_integer("parallelism", parallelism, MIN_PARALLELISM, MAX_PARALLELISM)
        self.parallelism = parallelism
        self.profile = "CUSTOM"
        return self

    def set_hash_len(self, hash_len: int) -> "Argon2ConfigBuilder":
        validate_integer("hash_len", hash_len, MIN_HASH_LEN, MAX_HASH_LEN)
        self.hash_len = hash_len
        return self

    def build(self) -> Argon2Config:

        if (self.profile is None
            or self.time_cost is None
            or self.memory_cost is None
            or self.parallelism is None):

            raise ValueError("Select a profile or configure all cost parameters")

        return Argon2Config(
            profile=self.profile,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=self.hash_len,
            version=ARGON2_VERSION
        )
