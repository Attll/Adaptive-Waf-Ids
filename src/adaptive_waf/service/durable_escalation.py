"""Opt-in RabbitMQ deep jobs with PostgreSQL leases and a result-reporting outbox.

Raw inspection payloads live only in the TTL-limited broker queue. PostgreSQL keeps job metadata and
redacted terminal outcomes. No prediction is a verified label. This adapter never changes live configuration.
"""
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
from threading import Event, Thread
from uuid import UUID, uuid4

from adaptive_waf.contracts import HttpRequestRecord
from adaptive_waf.service.escalation import _provisional
from adaptive_waf.service.runtime import _BoundedRunner

TERMINAL = {"COMPLETED", "FAILED", "EXPIRED"}


class JobStore:
    def __init__(self, dsn):
        self.dsn = dsn

    def connect(self):
        import psycopg
        from psycopg.rows import dict_row
        return psycopg.connect(self.dsn, connect_timeout=2, row_factory=dict_row,
                              options="-c statement_timeout=2000 -c lock_timeout=1000")

    def create(self, identifier, request_id, version, ttl, capacity):
        with self.connect() as db:
            db.execute("select pg_advisory_xact_lock(640641)")
            existing = db.execute("select state from deep_analysis_jobs where job_id=%s", (identifier,)).fetchone()
            if existing:
                return "EXISTING:" + existing["state"]
            count = db.execute("select count(*) n from deep_analysis_jobs where state in ('PENDING','RUNNING')").fetchone()["n"]
            if count >= capacity:
                return "FULL"
            db.execute("insert into deep_analysis_jobs(job_id,request_id,state,expires_at,model_version) values(%s,%s,'PENDING',%s,%s)",
                       (identifier, request_id, datetime.now(timezone.utc) + timedelta(seconds=ttl), version))
            return "CREATED"

    def get(self, identifier):
        with self.connect() as db:
            return db.execute("select * from deep_analysis_jobs where job_id=%s", (identifier,)).fetchone()

    def claim(self, identifier, owner, lease_seconds, attempts):
        with self.connect() as db:
            return db.execute("""update deep_analysis_jobs set state='RUNNING',attempts=attempts+1,
                lease_owner=%s,lease_until=now()+(%s * interval '1 second'),updated_at=now()
                where job_id=%s and expires_at>now() and attempts<%s
                and (state='PENDING' or (state='RUNNING' and lease_until<now())) returning *""",
                (owner, lease_seconds, identifier, attempts)).fetchone()

    def finish(self, identifier, owner, state, outcome):
        from psycopg.types.json import Jsonb
        with self.connect() as db:
            return db.execute("""update deep_analysis_jobs set state=%s,outcome=%s,updated_at=now(),lease_owner=null,lease_until=null
                where job_id=%s and state='RUNNING' and lease_owner=%s returning job_id""",
                (state, Jsonb(outcome), identifier, owner)).fetchone() is not None

    def retry(self, identifier, owner):
        with self.connect() as db:
            db.execute("update deep_analysis_jobs set state='PENDING',lease_owner=null,lease_until=null where job_id=%s and lease_owner=%s and state='RUNNING'",
                       (identifier, owner))

    def fail_publish(self, identifier):
        with self.connect() as db:
            db.execute("""update deep_analysis_jobs set state='FAILED',updated_at=now(),outcome=jsonb_build_object(
                'escalation_id',job_id::text,'request_id',request_id::text,'state','FAILED','error','PublishUnconfirmed')
                where job_id=%s and state='PENDING'""", (identifier,))

    def expire(self):
        with self.connect() as db:
            db.execute("""update deep_analysis_jobs set state='EXPIRED',updated_at=now(),outcome=jsonb_build_object(
                'escalation_id',job_id::text,'request_id',request_id::text,'state','EXPIRED','error','JobExpired')
                where state in ('PENDING','RUNNING') and expires_at<=now()""")

    def unreported(self):
        with self.connect() as db:
            return db.execute("select job_id,outcome from deep_analysis_jobs where outcome is not null and not reported order by updated_at limit 20").fetchall()

    def reported(self, identifier):
        with self.connect() as db:
            db.execute("update deep_analysis_jobs set reported=true where job_id=%s", (identifier,))

    def recent(self, limit,offset=0):
        with self.connect() as db:
            return db.execute("select job_id,request_id,state,attempts,model_version,created_at,updated_at,outcome from deep_analysis_jobs order by created_at desc,job_id desc limit %s offset %s",
                              (max(1, min(limit, 200)),max(0,min(offset,1000000)))).fetchall()

    def counts(self):
        with self.connect() as db:
            return {row["state"]: row["n"] for row in db.execute("select state,count(*) n from deep_analysis_jobs group by state")}


class DurableEscalationWorker:
    # New topology version adds raw-message retention on the dead queue. Existing v1 queues are untouched.
    queue = "adaptive.waf.deep.v2"
    dead_queue = "adaptive.waf.deep.dead.v2"

    def __init__(self, dsn, broker_url, workers=1, queue_limit=256, ttl_seconds=30, timeout_ms=5000, max_attempts=3, reporter=None):
        if min(workers, queue_limit, ttl_seconds, timeout_ms, max_attempts) <= 0:
            raise ValueError("deep job bounds must be positive")
        self.store = JobStore(dsn)
        self.broker_url, self.workers, self.capacity = broker_url, workers, queue_limit
        self.ttl, self.timeout_ms, self.max_attempts, self.reporter = ttl_seconds, timeout_ms, max_attempts, reporter
        self._adjudicator = None
        self._stop = Event()
        self._threads = []
        self._runner = _BoundedRunner(workers, 0, "durable-deep-model")
        self._rejected = 0
        self._last_error = None
        self._cached_queue_counts = None

    def _connection(self):
        import pika
        options = pika.URLParameters(self.broker_url)
        options.socket_timeout = 1
        options.stack_timeout = 3
        options.blocked_connection_timeout = 2
        options.heartbeat = 30
        options.connection_attempts = 1
        return pika.BlockingConnection(options)

    def _topology(self, channel):
        channel.queue_declare(self.dead_queue, durable=True, arguments={"x-max-length": 10000, "x-message-ttl": 60000})
        channel.queue_declare(self.queue, durable=True, arguments={"x-max-length": self.capacity, "x-overflow": "reject-publish",
            "x-message-ttl": self.ttl * 1000, "x-dead-letter-exchange": "", "x-dead-letter-routing-key": self.dead_queue})
        channel.basic_qos(prefetch_count=1)

    def bind(self, adjudicator):
        self._adjudicator = adjudicator

    def start(self):
        if self._threads:
            return
        # Probe schema/configuration before declaring the service ready.
        self._cached_queue_counts = self.store.counts()
        with self._connection() as connection:
            self._topology(connection.channel())
        for index in range(self.workers):
            thread = Thread(target=self._drain, daemon=True, name=f"durable-deep-{index}")
            self._threads.append(thread)
            thread.start()
        thread = Thread(target=self._maintenance, daemon=True, name="deep-result-outbox")
        self._threads.append(thread)
        thread.start()

    def close(self):
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=4)
        self._runner.close()

    def submit(self, identifier, request, result):
        import pika
        try:
            UUID(identifier)
            status = self.store.create(identifier, str(request.request_id), result.model_versions["deep"], self.ttl, self.capacity)
            if status == "FULL":
                self._rejected += 1
                return False
            if status.startswith("EXISTING:"):
                return status.split(':',1)[1] not in {"FAILED","EXPIRED"}
            payload = {"job_id": identifier, "request": asdict(request), "provisional": _provisional(result)}
            with self._connection() as connection:
                channel = connection.channel()
                self._topology(channel)
                channel.confirm_delivery()
                channel.basic_publish("", self.queue, json.dumps(payload, default=str).encode(), mandatory=True,
                                      properties=pika.BasicProperties(delivery_mode=2, content_type="application/json", message_id=identifier))
            return True
        except Exception as error:
            self._last_error = type(error).__name__
            self._rejected += 1
            try:
                self.store.fail_publish(identifier)
            except Exception:
                pass  # an unconfirmed PENDING row is expired by maintenance after recovery
            return False

    def _drain(self):
        while not self._stop.is_set():
            try:
                with self._connection() as connection:
                    channel = connection.channel()
                    self._topology(channel)
                    while not self._stop.is_set():
                        method, _, body = channel.basic_get(self.queue, auto_ack=False)
                        if method is None:
                            connection.process_data_events(time_limit=.1)
                            self._stop.wait(.05)
                            continue
                        self._process(channel, method.delivery_tag, body)
            except Exception as error:
                self._last_error = type(error).__name__
                self._stop.wait(.5)

    def _process(self, channel, delivery_tag, body):
        try:
            payload = json.loads(body)
            identifier = str(UUID(payload["job_id"]))
        except (ValueError, KeyError, TypeError):
            channel.basic_nack(delivery_tag, requeue=False)
            return
        job = self.store.get(identifier)
        if job is None or job["state"] in TERMINAL:
            channel.basic_ack(delivery_tag)
            return
        self.store.expire()
        owner = str(uuid4())
        job = self.store.claim(identifier, owner, self.timeout_ms / 1000 + 2, self.max_attempts)
        if job is None:
            current = self.store.get(identifier)
            channel.basic_nack(delivery_tag, requeue=current is not None and current["state"] not in TERMINAL)
            self._stop.wait(.1)
            return
        provisional = payload["provisional"]
        try:
            values = payload["request"]
            values["request_id"] = UUID(values["request_id"])
            values["received_at"] = datetime.fromisoformat(values["received_at"])
            request = HttpRequestRecord(**values)
            (deep, duration), timing = self._runner.call(self.timeout_ms, self._adjudicator, request)
            if deep.model_version != job["model_version"]:
                raise ValueError("job model version mismatch")
            state = "COMPLETED"
            outcome = {"escalation_id": identifier, "request_id": str(request.request_id), "method": request.method,
                       "path": request.path[:1024], "source_ip": request.source_ip, "query": "[REDACTED]",
                       "submitted_at": job["created_at"].isoformat(), "resolved_at": datetime.now(timezone.utc).isoformat(),
                       "queued_ms": max(0, (datetime.now(timezone.utc) - job["created_at"]).total_seconds() * 1000 - timing.elapsed_ms),
                       "deep_latency_ms": duration, "provisional": {"predicted_attack": provisional["attack"], "risk": provisional["risk"], "confidence": provisional["confidence"]},
                       "revised": {"predicted_attack": str(deep.predicted_attack), "risk": deep.risk, "confidence": deep.confidence,
                                   "model_version": deep.model_version, "class_scores": {str(k): v for k, v in deep.class_scores.items()}},
                       "changed": str(deep.predicted_attack) != provisional["attack"], "error": None}
        except Exception as error:
            if job["attempts"] < self.max_attempts and job["expires_at"] > datetime.now(timezone.utc):
                self.store.retry(identifier, owner)
                channel.basic_nack(delivery_tag, requeue=True)
                return
            state = "FAILED"
            outcome = {"escalation_id": identifier, "request_id": str(job["request_id"]), "changed": False, "error": type(error).__name__}
        if datetime.now(timezone.utc) >= job["expires_at"]:
            state, outcome = "EXPIRED", {"escalation_id": identifier, "request_id": str(job["request_id"]), "changed": False, "error": "JobExpired"}
        outcome["state"] = state
        self.store.finish(identifier, owner, state, outcome)
        if state == "FAILED":
            channel.basic_nack(delivery_tag, requeue=False)
        else:
            channel.basic_ack(delivery_tag)

    def _maintenance(self):
        while not self._stop.is_set():
            try:
                self.store.expire()
                self._cached_queue_counts = self.store.counts()
                if self.reporter:
                    for row in self.store.unreported():
                        class Outcome:
                            def as_payload(self):
                                return row["outcome"]
                        if self.reporter(Outcome()) is True:
                            self.store.reported(row["job_id"])
            except Exception as error:
                self._last_error = type(error).__name__
            self._stop.wait(.5)

    def recent(self, limit=50):
        outcomes = []
        for row in self.store.recent(limit):
            if not row["outcome"]:
                continue
            unknown = {"predicted_attack": "UNKNOWN", "risk": 0, "confidence": 0}
            outcomes.append({"method": "UNKNOWN", "path": "[REDACTED]", "source_ip": None,
                "submitted_at": row["created_at"].isoformat(), "resolved_at": row["updated_at"].isoformat(),
                "queued_ms": 0, "deep_latency_ms": 0, "provisional": unknown, "revised": unknown,
                "changed": False, **row["outcome"]})
        return outcomes

    def jobs(self, limit=50,offset=0):
        return [{"job_id": str(row["job_id"]), "request_id": str(row["request_id"]), "state": row["state"],
                 "attempts": row["attempts"], "model_version": row["model_version"], "created_at": row["created_at"].isoformat(),"outcome":row["outcome"]}
                for row in self.store.recent(limit,offset)]

    def statistics(self):
        counts = self.store.counts()
        return {"enabled": True, "backend": "rabbitmq_postgresql", "workers": self.workers, "queue_limit": self.capacity,
                "queue_depth": counts.get("PENDING", 0), "running": counts.get("RUNNING", 0),
                "pending": counts.get("PENDING", 0) + counts.get("RUNNING", 0), "submitted": sum(counts.values()),
                "resolved": counts.get("COMPLETED", 0), "failed": counts.get("FAILED", 0), "expired": counts.get("EXPIRED", 0),
                "rejected": self._rejected, "last_error_type": self._last_error}

    def cached_statistics(self):
        # No network I/O on the routing path. Maintenance refreshes this snapshot.
        counts=self._cached_queue_counts
        return None if counts is None else {"queue_depth":counts.get("PENDING",0)+counts.get("RUNNING",0),"queue_limit":self.capacity}
