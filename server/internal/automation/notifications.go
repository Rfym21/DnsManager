package automation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/dns-manager/dnsmgr/server/internal/notifications"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func (r *Runner) NotificationHandlers() map[string]Handler {
	return map[string]Handler{"notification_channels": r.testNotification, "delegations": r.testDelegation, "proxy_profiles": r.testProxy}
}
func (r *Runner) testNotification(ctx context.Context, j store.Job) (any, error) {
	if err := r.check(ctx, j); err != nil {
		return nil, err
	}
	o, err := r.Store.Object(ctx, j.ResourceID)
	if err != nil {
		return nil, err
	}
	var c notifications.Channel
	if err = json.Unmarshal(o.Data, &c); err != nil {
		return nil, err
	}
	client, err := r.Store.HTTPClient(ctx, c.Config, 20*time.Second)
	if err != nil {
		return nil, err
	}
	err = (notifications.Sender{Client: client}).Send(ctx, c, notifications.Message{Title: "DNS Manager通知测试", Body: "通知渠道连接测试。", Event: "test", ResourceID: o.ID})
	if err != nil {
		return nil, err
	}
	return map[string]bool{"delivered": true}, nil
}
func (r *Runner) testDelegation(ctx context.Context, j store.Job) (any, error) {
	o, err := r.Store.Object(ctx, j.ResourceID)
	if err != nil {
		return nil, err
	}
	var d struct {
		Domain string `json:"domain"`
		Target string `json:"target"`
	}
	if err = json.Unmarshal(o.Data, &d); err != nil {
		return nil, err
	}
	target, err := net.DefaultResolver.LookupCNAME(ctx, "_acme-challenge."+strings.TrimPrefix(d.Domain, "*."))
	if err != nil {
		return nil, err
	}
	return map[string]any{"matched": strings.EqualFold(strings.TrimSuffix(target, "."), strings.TrimSuffix(d.Target, ".")), "observed": target}, nil
}
func (r *Runner) QueueEvent(ctx context.Context, key string, message notifications.Message) error {
	return r.Store.QueueBusinessEvent(ctx, key, message)
}
func (r *Runner) notificationChannels(ctx context.Context, raw json.RawMessage) ([]string, error) {
	var message notifications.Message
	if err := json.Unmarshal(raw, &message); err != nil {
		return nil, err
	}
	channels, err := r.Store.Objects(ctx, "notification_channels")
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, o := range channels {
		if !o.Active {
			continue
		}
		var c notifications.Channel
		if json.Unmarshal(o.Data, &c) != nil {
			continue
		}
		allowed := len(c.Events) == 0
		for _, event := range c.Events {
			if event == message.Event || event == "*" {
				allowed = true
			}
		}
		if allowed {
			ids = append(ids, o.ID)
		}
	}
	return ids, nil
}
func (r *Runner) DeliverNotifications(ctx context.Context) error {
	for n := 0; n < 20; n++ {
		o, err := r.Store.ClaimNotification(ctx)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		release, lockErr := r.Store.LockResources(ctx, []string{"object:" + o.ChannelID})
		if lockErr != nil {
			if err := r.Store.FinishNotification(ctx, o, "retry", 5); err != nil {
				return err
			}
			continue
		}
		object, err := r.Store.Object(ctx, o.ChannelID)
		if err == nil {
			var c notifications.Channel
			var m notifications.Message
			if json.Unmarshal(object.Data, &c) != nil || json.Unmarshal(o.Payload, &m) != nil {
				err = errors.New("invalid notification payload")
			} else if !object.Active {
				err = errors.New("notification channel disabled")
			} else {
				client, e := r.Store.HTTPClient(ctx, c.Config, 20*time.Second)
				if e != nil {
					err = e
				} else {
					err = (notifications.Sender{Client: client}).Send(ctx, c, m)
				}
			}
		}
		release()
		state := "sent"
		if err != nil {
			state = "retry"
			if o.Attempts >= 5 {
				state = "failed"
			}
		}
		delay := time.Duration(1<<min(o.Attempts+1, 8)) * time.Second
		e := r.Store.FinishNotification(ctx, o, state, int(delay.Seconds()))
		if e != nil {
			return e
		}
	}
	return nil
}

// Events are persisted in the transaction that changes the business state.
// Dispatch is resumable without a time window or a fixed first-page starvation.
func (r *Runner) QueueTerminalEvents(ctx context.Context) error {
	for n := 0; n < 200; n++ {
		err := r.Store.DispatchOneEvent(ctx, func(raw json.RawMessage) ([]string, error) { return r.notificationChannels(ctx, raw) })
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}
