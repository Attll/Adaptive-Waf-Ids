"""Bounded, opt-in deep inference coalescing. Native execution is not cancellable."""
from collections import deque
from concurrent.futures import Future, TimeoutError as FutureTimeout
from threading import Condition, Thread
from time import monotonic


class BatchBusyError(RuntimeError):
    pass


class MicrobatchPredictor:
    def __init__(self, predictor, max_batch=8, wait_ms=2, queue_limit=32, timeout_seconds=1):
        if not 2 <= max_batch <= 32 or not 0 <= wait_ms <= 10 or not 1 <= queue_limit <= 256 or not 0 < timeout_seconds <= 30:
            raise ValueError('invalid microbatch bounds')
        self.predictor, self.max_batch = predictor, max_batch
        self.wait_seconds, self.queue_limit, self.timeout = wait_ms/1000, queue_limit, timeout_seconds
        self.condition, self.queue, self.thread = Condition(), deque(), None
        self.closed, self.inflight = False, []
        self.batches = self.completed = self.expired = self.rejected = 0
        self.caller_timeouts = 0
        self.total_queue_seconds = 0.

    def warm(self):
        self.predictor.warm()

    def __call__(self, request):
        return self.predict(request, self.timeout)

    def predict(self, request, timeout_seconds):
        if not 0 < timeout_seconds <= 30:
            raise ValueError('invalid microbatch deadline')
        future, submitted = Future(), monotonic()
        with self.condition:
            if self.closed:
                raise RuntimeError('microbatch predictor closed')
            if len(self.queue) >= self.queue_limit:
                self.rejected += 1
                raise BatchBusyError('deep microbatch queue full')
            self.queue.append((request,future,submitted+timeout_seconds,submitted))
            if self.thread is None:
                self.thread = Thread(target=self._run,name='deep-microbatch',daemon=True)
                self.thread.start()
            self.condition.notify()
        try:
            return future.result(timeout=max(0,submitted+timeout_seconds-monotonic()))
        except FutureTimeout:
            future.cancel()
            with self.condition:
                self.caller_timeouts += 1
            raise TimeoutError('deep microbatch deadline exceeded') from None

    def _run(self):
        while True:
            with self.condition:
                while not self.queue and not self.closed:
                    self.condition.wait()
                if self.closed:
                    return
                batch = [self.queue.popleft()]
                collection_deadline = min(monotonic()+self.wait_seconds,batch[0][2])
                while len(batch) < self.max_batch and not self.closed:
                    if monotonic() >= collection_deadline:
                        break
                    if self.queue:
                        batch.append(self.queue.popleft())
                        collection_deadline = min(collection_deadline,batch[-1][2])
                    else:
                        self.condition.wait(timeout=max(0,collection_deadline-monotonic()))
                if self.closed:
                    for _,future,_,_ in batch:
                        if not future.done():future.set_exception(RuntimeError('microbatch predictor closed'))
                    return
                active = []
                for job in batch:
                    _,future,deadline,submitted = job
                    if future.cancelled() or deadline <= monotonic():
                        self.expired += 1
                        if not future.done():future.set_exception(TimeoutError('deep microbatch expired in queue'))
                    else:
                        active.append(job)
                        self.total_queue_seconds += monotonic()-submitted
                self.inflight = active
            if not active:
                continue
            try:
                rows = self.predictor.predict_many([job[0] for job in active])
                if len(rows) != len(active):
                    raise ValueError('deep batch result cardinality mismatch')
                error = None
            except Exception as failure:
                rows, error = [], failure
            with self.condition:
                self.batches += 1
                for index,(_,future,deadline,_) in enumerate(active):
                    if future.done():continue
                    if deadline <= monotonic():
                        self.expired += 1
                        future.set_exception(TimeoutError('deep microbatch expired during inference'))
                    elif error:
                        future.set_exception(error)
                    else:
                        self.completed += 1
                        future.set_result(rows[index])
                self.inflight = []

    def statistics(self):
        with self.condition:
            return {'enabled':True,'queue_depth':len(self.queue),'inflight':len(self.inflight),
                    'max_batch':self.max_batch,'queue_limit':self.queue_limit,'wait_ms':self.wait_seconds*1000,
                    'batches':self.batches,'completed':self.completed,'expired':self.expired,'rejected':self.rejected,
                    'caller_timeouts':self.caller_timeouts,
                    'total_queue_wait_ms':self.total_queue_seconds*1000,'closed':self.closed}

    def close(self):
        with self.condition:
            self.closed = True
            for _,future,_,_ in [*self.queue,*self.inflight]:
                if not future.done():future.set_exception(RuntimeError('microbatch predictor closed'))
            self.queue.clear()
            self.condition.notify_all()
        if self.thread:
            self.thread.join(timeout=1)
