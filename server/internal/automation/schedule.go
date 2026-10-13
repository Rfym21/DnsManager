package automation

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Schedule struct {
	Mode            string `json:"mode"`
	Timezone        string `json:"timezone"`
	Time            string `json:"time"`
	Date            string `json:"date,omitempty"`
	Weekday         int    `json:"weekday,omitempty"`
	Monthday        int    `json:"monthday,omitempty"`
	IntervalSeconds int    `json:"interval_seconds,omitempty"`
	MissedPolicy    string `json:"missed_policy"`
}

// Next uses wall-clock calendar dates instead of adding 24h across DST boundaries.
// Missing local times are skipped; repeated wall-clock times run once at Go's
// resolved occurrence. This policy is explicit in the API's execution preview.
func (s Schedule) Next(after time.Time) (time.Time, error) {
	if s.MissedPolicy != "" && s.MissedPolicy != "skip" && s.MissedPolicy != "run_once" {
		return time.Time{}, errors.New("missed_policy must be skip or run_once")
	}
	zone := s.Timezone
	if zone == "" {
		zone = "Asia/Shanghai"
	}
	loc, err := time.LoadLocation(zone)
	if err != nil {
		return time.Time{}, errors.New("invalid IANA timezone")
	}
	if s.Mode == "interval" {
		if s.IntervalSeconds < 5 {
			return time.Time{}, errors.New("interval must be at least 5 seconds")
		}
		return after.Add(time.Duration(s.IntervalSeconds) * time.Second).UTC(), nil
	}
	if s.Mode == "once" {
		t, err := time.Parse(time.RFC3339, s.Date)
		if err != nil {
			t, err = time.ParseInLocation("2006-01-02T15:04", s.Date, loc)
			if err != nil {
				t, err = time.ParseInLocation("2006-01-02T15:04", s.Date+"T"+s.Time, loc)
			}
		}
		if err != nil {
			return time.Time{}, errors.New("once schedule requires an ISO date")
		}
		if t.After(after) {
			return t.UTC(), nil
		}
		return time.Time{}, nil
	}
	parts := strings.Split(s.Time, ":")
	if len(parts) != 2 {
		return time.Time{}, errors.New("time must use HH:mm")
	}
	h, e1 := strconv.Atoi(parts[0])
	m, e2 := strconv.Atoi(parts[1])
	if e1 != nil || e2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return time.Time{}, errors.New("invalid schedule time")
	}
	if s.Mode != "daily" && s.Mode != "weekly" && s.Mode != "monthly" {
		return time.Time{}, errors.New("invalid schedule mode")
	}
	if s.Mode == "weekly" && (s.Weekday < 0 || s.Weekday > 6) {
		return time.Time{}, errors.New("weekday must be 0–6")
	}
	if s.Mode == "monthly" && (s.Monthday < 1 || s.Monthday > 31) {
		return time.Time{}, errors.New("monthday must be 1–31")
	}
	local := after.In(loc)
	for n := 0; n < 740; n++ {
		day := time.Date(local.Year(), local.Month(), local.Day()+n, 12, 0, 0, 0, loc)
		if s.Mode == "weekly" && int(day.Weekday()) != s.Weekday {
			continue
		}
		if s.Mode == "monthly" && day.Day() != s.Monthday {
			continue
		}
		candidate := time.Date(day.Year(), day.Month(), day.Day(), h, m, 0, 0, loc)
		if candidate.Hour() != h || candidate.Minute() != m || candidate.Day() != day.Day() {
			continue
		}
		if candidate.After(after) {
			return candidate.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("no occurrence found for %s", s.Mode)
}
func (s Schedule) Preview(after time.Time, n int) ([]time.Time, error) {
	if n < 1 || n > 20 {
		n = 5
	}
	result := []time.Time{}
	for i := 0; i < n; i++ {
		next, err := s.Next(after)
		if err != nil {
			return nil, err
		}
		if next.IsZero() {
			break
		}
		result = append(result, next)
		after = next
	}
	return result, nil
}
