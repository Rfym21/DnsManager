package automation

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

type Handler func(context.Context, store.Job) (any, error)
type PartialError struct{ Message string }

func (e *PartialError) Error() string { return e.Message }

type UnknownError struct{ Message string }

func (e *UnknownError) Error() string { return e.Message }

type RetryError struct {
	Err   error
	After time.Duration
}

func (e *RetryError) Error() string { return e.Err.Error() }

type Worker struct {
	Store       *store.Store
	ID          string
	Concurrency int
	Lease       time.Duration
	Handlers    map[string]Handler
	Schedule    func(context.Context) error
}

func (w *Worker) Run(ctx context.Context) error {
	if w.ID == "" {
		id, err := store.ID()
		if err != nil {
			return err
		}
		w.ID = id
	}
	if w.Concurrency < 1 {
		w.Concurrency = 4
	}
	if w.Lease < 15*time.Second {
		w.Lease = 60 * time.Second
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	for n := 0; n < w.Concurrency; n++ {
		wg.Add(1)
		go func() { defer wg.Done(); w.loop(ctx) }()
	}
	// The scheduler and registry lookups must never delay heartbeat publication.
	wg.Add(3)
	go func() {
		defer wg.Done()
		runner := &Runner{Store: w.Store}
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			if err := runner.DeliverNotifications(ctx); err != nil && ctx.Err() == nil {
				slog.Error("notification delivery failed")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			if w.Schedule != nil {
				if err := w.Schedule(ctx); err != nil && ctx.Err() == nil {
					slog.Error("scheduler failed")
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	go func() {
		defer wg.Done()
		runner := &Runner{Store: w.Store}
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			if err := runner.cleanup(ctx); err != nil && ctx.Err() == nil {
				slog.Error("cleanup failed")
			}
			if err := runner.domainExpiry(ctx); err != nil && ctx.Err() == nil {
				slog.Error("expiry refresh failed")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if _, err := w.Store.DB.ExecContext(ctx, "INSERT INTO worker_heartbeats(worker_id,last_seen,capabilities) VALUES (?,UTC_TIMESTAMP(6),'[\"jobs\",\"scheduler\"]') ON DUPLICATE KEY UPDATE last_seen=UTC_TIMESTAMP(6)", w.ID); err != nil && ctx.Err() == nil {
			slog.Error("worker heartbeat failed")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
func (w *Worker) loop(ctx context.Context) {
	for ctx.Err() == nil {
		job, err := w.Store.ClaimJob(ctx, w.ID, w.Lease)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) && ctx.Err() == nil {
				slog.Error("job claim failed")
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(300 * time.Millisecond):
			}
			continue
		}
		w.execute(ctx, job)
	}
}
func (w *Worker) execute(parent context.Context, j store.Job) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-finished:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if w.Store.LeaseJob(ctx, j, w.Lease) != nil {
					cancel()
					return
				}
				current, e := w.Store.Job(ctx, j.ID)
				if e != nil || current.CancelRequested {
					cancel()
					return
				}
			}
		}
	}()
	handler, ok := w.Handlers[j.Kind]
	var result any
	var err error
	if !ok {
		err = errors.New("no executor registered for job kind")
	} else {
		p, e := (&Runner{Store: w.Store}).principal(ctx, j)
		if e != nil {
			err = e
		} else if j.Kind != "record_batch" && (!p.Admin() || !p.AllowsScope("admin")) {
			err = store.ErrForbidden
		} else {
			var release func()
			release, err = w.lockJobResources(ctx, j)
			if errors.Is(err, store.ErrResourceBusy) {
				err = &RetryError{Err: err, After: 5 * time.Second}
			}
			if err == nil {
				defer release()
				w.Store.AddJobEvent(ctx, j, "info", "开始执行任务", map[string]any{"attempt": j.Attempt})
				result, err = invoke(ctx, j, handler)
			}
		}
	}
	if parent.Err() != nil {
		return
	} // lease expiration enables checkpoint-based recovery
	finishCtx, finishCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer finishCancel()
	state, code, message, next := "succeeded", "", "", time.Time{}
	current, e := w.Store.Job(finishCtx, j.ID)
	requestedCancel := e == nil && current.CancelRequested && current.LeaseOwner == j.LeaseOwner && current.FencingToken == j.FencingToken
	if err != nil {
		state, code, message = "failed", "execution_failed", safeError(err)
		var partial *PartialError
		var unknown *UnknownError
		var retry *RetryError
		var deferred *DeferredError
		var remote *dns.RemoteError
		var uncertain interface{ UnknownResult() bool }
		if errors.As(err, &partial) {
			state, code = "partial", "partial_failure"
		}
		if errors.As(err, &unknown) {
			state, code = "unknown", "result_unknown"
		}
		if errors.As(err, &remote) && remote.UnknownResult {
			state, code = "unknown", "result_unknown"
		}
		if errors.As(err, &uncertain) && uncertain.UnknownResult() {
			state, code = "unknown", "result_unknown"
		}
		if errors.As(err, &retry) && (j.Attempt < j.MaxAttempts || errors.Is(err, store.ErrResourceBusy)) {
			state, code = "retry", "retry_scheduled"
			if errors.Is(err, store.ErrResourceBusy) {
				code = "resource_busy"
			}
			delay := retry.After
			if delay <= 0 {
				delay = time.Duration(1<<min(j.Attempt, 8))*time.Second + time.Duration(rand.IntN(1000))*time.Millisecond
			}
			next = time.Now().Add(delay)
		}
		if errors.As(err, &deferred) {
			state, code, next = "retry", "window_wait", deferred.Until
		}
		if errors.Is(err, store.ErrCancelled) {
			state, code = "cancelled", "cancelled"
		}
		if errors.Is(err, store.ErrLeaseLost) || (errors.Is(err, context.Canceled) && !requestedCancel) {
			return
		}
	}
	if requestedCancel && (errors.Is(err, context.Canceled) || errors.Is(err, store.ErrCancelled)) {
		state, code, message = "cancelled", "cancelled", "任务已取消"
	}
	if err = w.Store.CompleteJob(finishCtx, j, state, result, code, message, next); err != nil {
		slog.Error("job completion not saved", "job_id", j.ID)
		return
	}
}

func invoke(ctx context.Context, j store.Job, handler Handler) (result any, err error) {
	defer func() {
		if recover() != nil {
			result = nil
			err = &UnknownError{Message: "执行器异常中断，需核对外部结果后重试"}
		}
	}()
	return handler(ctx, j)
}
