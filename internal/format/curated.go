package format

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Record is one envelope item with its {value:X} fields already unwrapped.
type Record struct {
	ID, Type, Name, UIURL        string
	GroupUniqueID, AssetUniqueID string // top-level identifiers, when present
	Fields                       map[string]any
}

// Envelope is the shape shared by every Orca MCP tool response.
type Envelope struct {
	Records []Record
	Total   int
	AppURL  string
}

// ParseEnvelope decodes a tool response's text into an Envelope.
func ParseEnvelope(text string) (*Envelope, error) {
	var raw struct {
		Data []struct {
			ID      string         `json:"id"`
			Type    string         `json:"type"`
			Name    string         `json:"name"`
			UIURL   string         `json:"ui_url"`
			GroupID string         `json:"group_unique_id"`
			AssetID string         `json:"asset_unique_id"`
			Data    map[string]any `json:"data"`
		} `json:"data"`
		Total  int    `json:"total_items"`
		AppURL string `json:"app_url"`
	}
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, fmt.Errorf("unexpected response (not an Orca envelope): %w", err)
	}
	env := &Envelope{Total: raw.Total, AppURL: raw.AppURL}
	for _, d := range raw.Data {
		fields := map[string]any{}
		for k, v := range d.Data {
			fields[k] = Unwrap(v)
		}
		env.Records = append(env.Records, Record{ID: d.ID, Type: d.Type, Name: d.Name, UIURL: d.UIURL,
			GroupUniqueID: d.GroupID, AssetUniqueID: d.AssetID, Fields: fields})
	}
	if env.Total == 0 {
		env.Total = len(env.Records) // some tools return total_items: null
	}
	return env, nil
}

// Field is one curated key/value; Curated preserves order.
type Field struct {
	Key   string
	Value any
}

type Curated []Field

// Text renders one "key: value" line per field.
func (c Curated) Text() string {
	var sb strings.Builder
	for _, f := range c {
		fmt.Fprintf(&sb, "%s: %s\n", f.Key, scalar(f.Value))
	}
	return sb.String()
}

// Line renders the values only, joined by " | ".
func (c Curated) Line() string {
	vals := make([]string, len(c))
	for i, f := range c {
		vals[i] = scalar(f.Value)
	}
	return strings.Join(vals, " | ")
}

// Map is the JSON form of the same fields.
func (c Curated) Map() map[string]any {
	m := make(map[string]any, len(c))
	for _, f := range c {
		m[f.Key] = f.Value
	}
	return m
}

func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = scalar(e)
		}
		return strings.Join(parts, ",")
	case map[string]any:
		b, _ := json.Marshal(t)
		return string(b)
	}
	return fmt.Sprint(v)
}

// pick appends key=fields[src] when present and non-empty.
func (c Curated) pick(r Record, key, src string) Curated {
	v, ok := r.Fields[src]
	if !ok || v == nil || v == "" {
		return c
	}
	if l, isList := v.([]any); isList && len(l) == 0 {
		return c
	}
	return append(c, Field{key, v})
}

func (c Curated) add(key string, v any) Curated {
	if v == nil || v == "" {
		return c
	}
	return append(c, Field{key, v})
}

func assetData(r Record) map[string]any {
	m, _ := r.Fields["AssetData"].(map[string]any)
	return m
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// Alert curates an alert record for `alert get`.
func Alert(r Record) Curated {
	var c Curated
	for _, k := range []string{"AlertId", "Title", "RiskLevel", "OrcaScore", "Status", "Category", "CveIds", "Labels"} {
		c = c.pick(r, k, k)
	}
	ad := assetData(r)
	asset := str(ad, "asset_name")
	if t := str(ad, "asset_type"); t != "" {
		asset = strings.TrimSpace(asset + " (" + t + ")")
	}
	asset = strings.TrimSpace(asset + " " + str(ad, "account_name"))
	c = c.add("Asset", asset)
	c = c.pick(r, "Recommendation", "Recommendation")
	return c.add("ui_url", r.UIURL)
}

// Asset curates an asset record for `asset get`.
func Asset(r Record) Curated {
	var c Curated
	for _, p := range [][2]string{{"Name", "Name"}, {"Type", "Type"}, {"RiskLevel", "RiskLevel"}, {"OrcaScore", "OrcaScore"},
		{"State", "State"}, {"Region", "Region"}, {"Exposure", "Exposure"}, {"IsCrownJewel", "IsCrownJewel"},
		{"TotalVulnerabilitiesFound", "TotalVulnerabilitiesFound"}} {
		c = c.pick(r, p[0], p[1])
	}
	return c.add("ui_url", r.UIURL)
}

// SearchRow curates one discovery_search result, switching on type.
func SearchRow(r Record) Curated {
	c := Curated{{"type", r.Type}}
	if r.Type == "Alert" {
		for _, k := range []string{"AlertId", "RiskLevel", "OrcaScore", "Status", "Title"} {
			c = c.pick(r, k, k)
		}
		return c.add("asset", str(assetData(r), "asset_name"))
	}
	name := r.Name
	if n, ok := r.Fields["Name"].(string); ok && n != "" {
		name = n
	}
	c = c.add("id", r.ID).add("name", name)
	return c.pick(r, "RiskLevel", "RiskLevel")
}

// Select picks the named top-level fields in the order given; names that are
// absent or empty are omitted.
func Select(r Record, fields []string) Curated {
	var c Curated
	for _, k := range fields {
		c = c.pick(r, k, k)
	}
	return c
}

// ID returns the identifier `asset get` and `alert get` accept: AlertId for
// alerts, AssetUniqueId otherwise. Empty when the record lacks it.
func ID(r Record) string {
	key := "AssetUniqueId"
	if r.Type == "Alert" {
		key = "AlertId"
	}
	if s, _ := r.Fields[key].(string); s != "" {
		return s
	}
	if r.Type != "Alert" {
		return r.AssetUniqueID
	}
	return ""
}

// JSON renders the fields as one compact object, keeping their order.
func (c Curated) JSON() string {
	var sb strings.Builder
	sb.WriteByte('{')
	for i, f := range c {
		if i > 0 {
			sb.WriteByte(',')
		}
		k, _ := json.Marshal(f.Key)
		v, _ := json.Marshal(f.Value)
		sb.Write(k)
		sb.WriteByte(':')
		sb.Write(v)
	}
	sb.WriteByte('}')
	return sb.String()
}

var tsvCell = strings.NewReplacer("\t", " ", "\n", " ", "\r", " ")

// TSV renders a header row and one row per record. columns nil means the
// union of keys in first-seen order. Missing values are empty cells.
func TSV(columns []string, rows []Curated) string {
	if columns == nil {
		seen := map[string]bool{}
		for _, r := range rows {
			for _, f := range r {
				if !seen[f.Key] {
					seen[f.Key] = true
					columns = append(columns, f.Key)
				}
			}
		}
	}
	var sb strings.Builder
	sb.WriteString(strings.Join(columns, "\t") + "\n")
	for _, r := range rows {
		cells := make([]string, len(columns))
		for i, col := range columns {
			for _, f := range r {
				if f.Key == col {
					cells[i] = tsvCell.Replace(scalar(f.Value))
				}
			}
		}
		sb.WriteString(strings.Join(cells, "\t") + "\n")
	}
	return sb.String()
}
