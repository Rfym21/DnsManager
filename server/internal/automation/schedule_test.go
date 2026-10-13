package automation

import (
	"testing"
	"time"
)

func TestScheduleCalendar(t *testing.T) {
	after := time.Date(2026, 1, 31, 8, 0, 0, 0, time.UTC)
	s := Schedule{Mode: "monthly", Timezone: "Asia/Shanghai", Time: "09:00", Monthday: 31}
	next, err := s.Next(after)
	if err != nil {
		t.Fatal(err)
	}
	expected := time.Date(2026, 3, 31, 1, 0, 0, 0, time.UTC)
	if !next.Equal(expected) {
		t.Fatalf("monthday31 should skip February: %v", next)
	}
	once := Schedule{Mode: "once", Date: "2026-01-01T00:00:00Z"}
	next, err = once.Next(after)
	if err != nil || !next.IsZero() {
		t.Fatalf("expired one-shot: %v %v", next, err)
	}
}
func TestScheduleDST(t *testing.T) {
	s := Schedule{Mode: "daily", Timezone: "America/New_York", Time: "02:30"}
	after := time.Date(2026, 3, 7, 8, 0, 0, 0, time.UTC)
	next, err := s.Next(after)
	if err != nil {
		t.Fatal(err)
	}
	if next.In(mustZone(t, "America/New_York")).Day() != 9 {
		t.Fatalf("nonexistent wall time should skip: %v", next)
	}
}
func mustZone(t *testing.T, name string) *time.Location {
	l, e := time.LoadLocation(name)
	if e != nil {
		t.Fatal(e)
	}
	return l
}
