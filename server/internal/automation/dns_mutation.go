package automation

import (
	"context"
	"encoding/json"
	"errors"
	"net"

	"github.com/dns-manager/dnsmgr/server/internal/providers/dns"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

type mutationIntent struct {
	Operation string     `json:"operation"`
	Record    dns.Record `json:"record"`
	Result    dns.Record `json:"result"`
}

func (r *Runner) recordForMutation(ctx context.Context, j store.Job, p dns.Provider, id string) (dns.Record, error) {
	items, err := r.Store.JobItems(ctx, j.ID)
	if err != nil {
		return dns.Record{}, err
	}
	if len(items) > 0 {
		var intent mutationIntent
		if json.Unmarshal(items[0].Detail, &intent) != nil || intent.Record.ID == "" {
			return dns.Record{}, errors.New("invalid DNS intent")
		}
		return intent.Record, nil
	}
	return p.GetRecord(ctx, id)
}

// An intent survives process death between a provider write and local commit.
// Reclaimed attempts can observe it, but cannot silently resubmit that write.
func (r *Runner) mutateDNS(ctx context.Context, j store.Job, p dns.Provider, index int, operation string, record dns.Record) (dns.Record, error) {
	items, err := r.Store.JobItems(ctx, j.ID)
	if err != nil {
		return dns.Record{}, err
	}
	intent := mutationIntent{Operation: operation, Record: record}
	for _, item := range items {
		if item.Index != index {
			continue
		}
		if json.Unmarshal(item.Detail, &intent) != nil || intent.Operation == "" {
			return dns.Record{}, errors.New("invalid DNS intent")
		}
		if item.State == "succeeded" {
			return intent.Result, nil
		}
		if item.State == "failed" {
			return dns.Record{}, errors.New("此前DNS写入被拒绝，请通过任务恢复重试")
		}
		observed, confirmed, e := dns.ObserveMutation(ctx, p, intent.Operation, intent.Record)
		if e != nil {
			return dns.Record{}, e
		}
		if !confirmed {
			return dns.Record{}, &UnknownError{Message: "此前DNS写入结果未唯一确认，请在任务中心核对"}
		}
		intent.Result = observed
		detail, _ := json.Marshal(intent)
		if e = r.Store.SaveJobItem(ctx, j, store.JobItem{Index: index, ResourceID: observed.ID, State: "succeeded", Detail: detail}); e != nil {
			return dns.Record{}, e
		}
		return observed, nil
	}
	if err = r.check(ctx, j); err != nil {
		return dns.Record{}, err
	}
	detail, _ := json.Marshal(intent)
	if err = r.Store.SaveJobItem(ctx, j, store.JobItem{Index: index, ResourceID: record.ID, State: "running", Detail: detail}); err != nil {
		return dns.Record{}, err
	}
	result := record
	switch operation {
	case "create":
		result, err = p.CreateRecord(ctx, record)
	case "update":
		result, err = p.UpdateRecord(ctx, record.ID, record)
	case "delete":
		err = p.DeleteRecord(ctx, record.ID)
	case "enable", "disable":
		err = p.SetStatus(ctx, record.ID, operation == "enable")
		result.Enabled = operation == "enable"
	case "remark":
		err = p.SetRemark(ctx, record.ID, record.Remark)
	default:
		err = errors.New("invalid DNS mutation")
	}
	state := "succeeded"
	if err != nil {
		state = "failed"
		var network net.Error
		var remote *dns.RemoteError
		if errors.As(err, &network) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || (errors.As(err, &remote) && remote.UnknownResult) {
			state = "unknown"
		}
	}
	intent.Result = result
	detail, _ = json.Marshal(intent)
	if saved := r.Store.SaveJobItem(ctx, j, store.JobItem{Index: index, ResourceID: result.ID, State: state, Detail: detail}); saved != nil {
		return dns.Record{}, saved
	}
	if state == "unknown" {
		return result, &UnknownError{Message: "DNS写入结果未知，请核对后恢复"}
	}
	return result, err
}
