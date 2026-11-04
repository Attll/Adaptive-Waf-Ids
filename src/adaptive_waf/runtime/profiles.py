"""Endpoint structure learned only from explicitly verified benign observations."""
from threading import RLock
import math
import json
from pathlib import Path
from urllib.parse import parse_qsl


class EndpointProfiles:
    def __init__(self, version, maximum_endpoints=1000, maximum_observations=100000, maximum_values=512):
        if not version or min(maximum_endpoints, maximum_observations, maximum_values) <= 0:
            raise ValueError("profile version and positive capacity required")
        self.version, self.maximum = version, maximum_endpoints
        self.profiles = {}
        self.seen = set()
        self.maximum_observations, self.maximum_values = maximum_observations, maximum_values
        self.lock = RLock()
        self.frozen = False

    @staticmethod
    def structure(request):
        keys = {key for key, _ in parse_qsl(request.query, keep_blank_values=True, max_num_fields=512)}
        content_type = next((v.split(';')[0].strip().lower() for k,v in request.headers.items() if k.lower() == "content-type"), "")
        return keys, content_type, len(request.body) + len(request.query)

    def observe(self, request, observation_id, verified_label):
        with self.lock:
            return self._observe(request, observation_id, verified_label)

    def _observe(self, request, observation_id, verified_label):
        if verified_label != "VERIFIED_BENIGN" or not observation_id:
            raise ValueError("only verified benign observations may update endpoint profiles")
        if observation_id in self.seen:
            return
        if self.frozen:
            raise ValueError("frozen profile requires a new reviewed artifact version")
        if len(self.seen) >= self.maximum_observations:
            raise ValueError("profile observation capacity exhausted; create a new reviewed profile version")
        endpoint = request.path
        if endpoint not in self.profiles and len(self.profiles) >= self.maximum:
            raise ValueError("endpoint profile capacity exhausted")
        keys, content_type, length = self.structure(request)
        profile = self.profiles.setdefault(endpoint, {"methods": set(), "content_types": set(), "parameters": set(), "count": 0, "mean": 0., "m2": 0.})
        if any(len(profile[name] | values) > self.maximum_values for name, values in
               (("methods", {request.method.upper()}), ("content_types", {content_type}), ("parameters", keys))):
            raise ValueError("profile structure capacity exhausted")
        profile["methods"].add(request.method.upper())
        profile["content_types"].add(content_type)
        profile["parameters"].update(keys)
        profile["count"] += 1
        delta = length - profile["mean"]
        profile["mean"] += delta / profile["count"]
        profile["m2"] += delta * (length - profile["mean"])
        self.seen.add(observation_id)

    def score(self, request):
        with self.lock:
            try:
                return self._score(request)
            except ValueError:
                return {"score":1.,"available":False,"reason":"structure_capacity_exceeded","profile_version":self.version}

    def save(self, path, review_reference):
        if not review_reference:
            raise ValueError("profile export requires reviewed benign provenance")
        with self.lock:
            value={"schema_version":1,"version":self.version,"review_reference":review_reference,
                "profiles":{endpoint:{name:sorted(item) if isinstance(item,set) else item for name,item in profile.items()}
                    for endpoint,profile in self.profiles.items()},"observation_ids":sorted(self.seen)}
            with Path(path).open("x",encoding="utf-8") as destination:
                json.dump(value,destination,indent=2,allow_nan=False)
            self.frozen=True

    @classmethod
    def load(cls, path):
        path=Path(path)
        if path.stat().st_size>10_000_000:
            raise ValueError("profile artifact exceeds capacity")
        value=json.loads(path.read_text(encoding="utf-8"))
        if value.get("schema_version")!=1 or not value.get("review_reference"):
            raise ValueError("invalid profile artifact schema/provenance")
        instance=cls(value["version"])
        if len(value["profiles"])>instance.maximum or len(value["observation_ids"])>instance.maximum_observations:
            raise ValueError("profile artifact exceeds capacity")
        for endpoint,profile in value["profiles"].items():
            if not endpoint.startswith('/') or profile["count"]<1 or any(not math.isfinite(profile[name]) or profile[name]<0 for name in ("mean","m2")):
                raise ValueError("invalid endpoint statistics")
            for name in ("methods","content_types","parameters"):
                if not isinstance(profile[name],list) or len(profile[name])>instance.maximum_values or not all(isinstance(item,str) for item in profile[name]):
                    raise ValueError("invalid endpoint structure")
                profile[name]=set(profile[name])
        instance.profiles=value["profiles"]
        instance.seen=set(value["observation_ids"])
        instance.frozen=True
        return instance

    def _score(self, request):
        profile = self.profiles.get(request.path)
        if not profile or profile["count"] < 5:
            return {"score": 0., "available": False, "profile_version": self.version}
        keys, content_type, length = self.structure(request)
        std = math.sqrt(profile["m2"] / max(1, profile["count"] - 1))
        score = .25 * (request.method.upper() not in profile["methods"]) + .25 * (content_type not in profile["content_types"])
        score += .25 * bool(keys - profile["parameters"])
        score += .25 * (abs(length - profile["mean"]) > max(32, 4 * std))
        return {"score": score, "available": True, "profile_version": self.version}
