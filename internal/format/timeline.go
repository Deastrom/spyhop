package format

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Event is one alert timeline entry.
type Event struct {
	CreateTime, Type, Description, From, To, UserEmail string
}

// Line renders `create_time type description [from→to] [user_email]`.
func (e Event) Line() string {
	parts := []string{e.CreateTime, e.Type, e.Description}
	if e.From != "" || e.To != "" {
		parts = append(parts, e.From+"→"+e.To)
	}
	if e.UserEmail != "" {
		parts = append(parts, e.UserEmail)
	}
	return strings.Join(parts, " ")
}

// ParseTimeline decodes get_alert_timeline's `{event_log:[...]}` (not the
// usual envelope), returning typed events and the raw event array.
func ParseTimeline(text string) ([]Event, []any, error) {
	var raw struct {
		EventLog []map[string]any `json:"event_log"`
	}
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, nil, fmt.Errorf("unexpected timeline response: %w", err)
	}
	events := make([]Event, len(raw.EventLog))
	rawEvents := make([]any, len(raw.EventLog))
	for i, m := range raw.EventLog {
		rawEvents[i] = m
		d, _ := m["details"].(map[string]any)
		events[i] = Event{
			CreateTime:  scalarOrEmpty(m["create_time"]),
			Type:        scalarOrEmpty(m["type"]),
			Description: scalarOrEmpty(d["description"]),
			From:        scalarOrEmpty(d["from"]),
			To:          scalarOrEmpty(d["to"]),
			UserEmail:   scalarOrEmpty(m["user_email"]),
		}
	}
	return events, rawEvents, nil
}

func scalarOrEmpty(v any) string {
	if v == nil {
		return ""
	}
	return scalar(v)
}

// AttackPath unwraps an attack-path envelope into compact JSON of its records
// and the total count.
func AttackPath(text string) (records string, total int, err error) {
	var raw struct {
		Data  []any `json:"data"`
		Total int   `json:"total_items"`
	}
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return "", 0, fmt.Errorf("unexpected attack path response: %w", err)
	}
	if raw.Data == nil {
		raw.Data = []any{}
	}
	b, err := json.Marshal(Unwrap(raw.Data))
	return string(b), raw.Total, err
}
