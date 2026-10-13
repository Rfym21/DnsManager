package automation

import (
	"context"
	"encoding/json"
	"github.com/dns-manager/dnsmgr/server/internal/store"
)

func (w *Worker) lockJobResources(ctx context.Context, j store.Job) (func(), error) {
	keys := []string{}
	ids := []string{}
	if j.ResourceID != "" {
		keys = append(keys, "object:"+j.ResourceID)
	}
	if j.DomainID != "" {
		ids = append(ids, j.DomainID)
	}
	if j.Kind == "record_batch" {
		var payload struct {
			DomainIDs []string `json:"domain_ids"`
		}
		if err := json.Unmarshal(j.Payload, &payload); err != nil {
			return nil, err
		}
		ids = append(ids, payload.DomainIDs...)
	}
	if j.Kind == "certificates" {
		if object, err := w.Store.Object(ctx,j.ResourceID); err == nil {
			var data CertificateData
			if json.Unmarshal(object.Data,&data)==nil && data.AccountID!="" { keys=append(keys,"object:"+data.AccountID) }
		}
		accounts, err := w.Store.Accounts(ctx)
		if err != nil {
			return nil, err
		}
		for _, a := range accounts {
			keys = append(keys, "dns-account:"+a.ID)
		}
	}
	if j.Kind == "deployments" {
		if object,err:=w.Store.Object(ctx,j.ResourceID);err==nil {
			var data DeploymentData
			if json.Unmarshal(object.Data,&data)==nil {keys=append(keys,"object:"+data.AccountID,"object:"+data.CertificateID)}
		}
	}
	for _, id := range ids {
		d, err := w.Store.Domain(ctx, id)
		if err != nil {
			return nil, err
		}
		keys = append(keys, "dns-account:"+d.AccountID)
	}
	return w.Store.LockResources(ctx, keys)
}
