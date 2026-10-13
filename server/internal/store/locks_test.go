package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestResourceLocksKeepLeasePoolAvailableAndSerializeOtherSessions(t *testing.T) {
	s := integrationStore(t)
	ctx := context.Background()
	id, _ := ID()
	s.DB.SetMaxOpenConns(1)
	keys := []string{"z:" + id, "a:" + id}
	release, e := s.LockResources(ctx, keys)
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	if keys[0] != "z:"+id {
		t.Fatal("caller keys changed")
	}
	probe, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if e = s.DB.PingContext(probe); e != nil {
		t.Fatal("session locks consumed lease pool", e)
	}
	if _, e = s.LockResources(probe, keys); !errors.Is(e, ErrResourceBusy) {
		t.Fatal("parallel writer acquired locks", e)
	}
	release()
	again, e := s.LockResources(probe, keys)
	if e != nil {
		t.Fatal("released lock retained", e)
	}
	again()
}
