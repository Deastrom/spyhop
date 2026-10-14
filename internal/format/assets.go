package format

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// RiskOrder is the display order for alert counts.
var RiskOrder = []string{"critical", "high", "medium", "low", "informational"}

// RiskCounts parses get_asset_alerts_count_grouped_by_risk_level
// (`data[{key:{RiskLevel},value}]`). Levels the tool omits count as 0.
func RiskCounts(text string) (map[string]int, error) {
	var raw struct {
		Data []struct {
			Key   map[string]any `json:"key"`
			Value float64        `json:"value"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, fmt.Errorf("unexpected counts response: %w", err)
	}
	counts := map[string]int{}
	for _, l := range RiskOrder {
		counts[l] = 0
	}
	for _, d := range raw.Data {
		level, _ := d.Key["RiskLevel"].(string)
		counts[strings.ToLower(level)] = int(d.Value)
	}
	return counts, nil
}

// CountsLine renders `critical 3 high 5 ...` in RiskOrder.
func CountsLine(counts map[string]int) string {
	parts := make([]string, 0, 2*len(RiskOrder))
	for _, l := range RiskOrder {
		parts = append(parts, l, fmt.Sprint(counts[l]))
	}
	return strings.Join(parts, " ")
}

// CountsJSON renders the counts as an object in RiskOrder.
func CountsJSON(counts map[string]int) string {
	parts := make([]string, len(RiskOrder))
	for i, l := range RiskOrder {
		parts[i] = fmt.Sprintf("%q:%d", l, counts[l])
	}
	return "{" + strings.Join(parts, ",") + "}"
}

var alertRowKeys = []string{"name", "risk_level", "orca_score", "status", "alert_title", "ui_url"}

// AlertSummaryRows parses get_asset_related_alerts_summary's flat rows.
func AlertSummaryRows(text string) ([]Curated, error) {
	var raw struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, fmt.Errorf("unexpected alert summary response: %w", err)
	}
	rows := make([]Curated, len(raw.Data))
	for i, m := range raw.Data {
		r := Record{Fields: m}
		for _, k := range alertRowKeys {
			rows[i] = rows[i].pick(r, k, k)
		}
	}
	return rows, nil
}

// AlertSummaryLine renders a row without its ui_url.
func AlertSummaryLine(c Curated) string {
	var vals []string
	for _, f := range c {
		if f.Key != "ui_url" {
			vals = append(vals, scalar(f.Value))
		}
	}
	return strings.Join(vals, " | ")
}

var markup = regexp.MustCompile(`\[[^\[\]|]*\|\|([^\[\]|]*)\|\|[^\[\]]*\]`)

// StripMarkup reduces `[type||name||id]` references to `name`.
func StripMarkup(s string) string { return markup.ReplaceAllString(s, "$1") }

// AttackPathLines parses get_asset_related_attack_paths_summary into one line
// per path: `id | target-name | first story sentence`.
func AttackPathLines(text string) (lines []string, total int, err error) {
	var raw struct {
		Data []struct {
			ID     string `json:"id"`
			Assets []struct {
				Name     string `json:"name"`
				IsTarget bool   `json:"is_target"`
			} `json:"involved_assets"`
			Story []string `json:"story"`
		} `json:"data"`
		Total int `json:"total_items"`
	}
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, 0, fmt.Errorf("unexpected attack paths response: %w", err)
	}
	for _, p := range raw.Data {
		var targets []string
		for _, a := range p.Assets {
			if a.IsTarget {
				targets = append(targets, a.Name)
			}
		}
		story := ""
		if len(p.Story) > 0 {
			story = StripMarkup(p.Story[0])
		}
		lines = append(lines, strings.Join([]string{p.ID, strings.Join(targets, ","), story}, " | "))
	}
	total = raw.Total
	if total == 0 {
		total = len(raw.Data)
	}
	return lines, total, nil
}

// CrownJewel parses get_asset_crown_jewel_info into is_crown_jewel, source,
// reason and score (the last two only when auto-detected details exist).
func CrownJewel(text string) (Curated, error) {
	var raw struct {
		Is      bool `json:"is_crown_jewel"`
		Details struct {
			Source string `json:"source"`
			Auto   *struct {
				Score  any    `json:"detected_crown_jewel_score"`
				Reason string `json:"detected_crown_jewel_reason"`
			} `json:"auto_detected_details"`
		} `json:"details"`
	}
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, fmt.Errorf("unexpected crown jewel response: %w", err)
	}
	c := Curated{{"is_crown_jewel", raw.Is}}.add("source", raw.Details.Source)
	if a := raw.Details.Auto; a != nil {
		c = c.add("reason", a.Reason).add("score", a.Score)
	}
	return c, nil
}

// Docs parses documentation_search into the answer and its source lines.
func Docs(text string) (answer string, sources []string, err error) {
	var raw struct {
		Answer  string `json:"answer"`
		Sources []any  `json:"sources"`
	}
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return "", nil, fmt.Errorf("unexpected docs response: %w", err)
	}
	for _, s := range raw.Sources {
		switch t := s.(type) {
		case string:
			sources = append(sources, t)
		case map[string]any:
			sources = append(sources, strings.TrimSpace(scalarOrEmpty(t["name"])+" "+scalarOrEmpty(t["link"])))
		}
	}
	return raw.Answer, sources, nil
}

// CVESummary is the curated view of get_cve_from_catalog.
type CVESummary struct {
	CVEID        string
	Detected     bool
	Hits         int
	Products     []string // at most 10 distinct
	ProductsMore int
	VendorIDs    []string
}

const maxProducts = 10

// CVE parses get_cve_from_catalog.
func CVE(text string) (CVESummary, error) {
	var raw struct {
		CVEID    string `json:"cve_id"`
		Detected bool   `json:"detected"`
		Hits     []struct {
			Product   string   `json:"product"`
			VendorIDs []string `json:"vendor_ids"`
		} `json:"hits"`
	}
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return CVESummary{}, fmt.Errorf("unexpected cve response: %w", err)
	}
	s := CVESummary{CVEID: raw.CVEID, Detected: raw.Detected, Hits: len(raw.Hits)}
	seenP, seenV := map[string]bool{}, map[string]bool{}
	var products []string
	for _, h := range raw.Hits {
		if h.Product != "" && !seenP[h.Product] {
			seenP[h.Product] = true
			products = append(products, h.Product)
		}
		for _, v := range h.VendorIDs {
			if !seenV[v] {
				seenV[v] = true
				s.VendorIDs = append(s.VendorIDs, v)
			}
		}
	}
	sort.Strings(s.VendorIDs)
	if len(products) > maxProducts {
		s.ProductsMore = len(products) - maxProducts
		products = products[:maxProducts]
	}
	s.Products = products
	return s, nil
}

// Text renders the summary as key: value lines.
func (s CVESummary) Text() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "cve_id: %s\ndetected: %t\nhits: %d\n", s.CVEID, s.Detected, s.Hits)
	if len(s.Products) > 0 {
		sb.WriteString("products: " + strings.Join(s.Products, ","))
		if s.ProductsMore > 0 {
			fmt.Fprintf(&sb, " …%d more", s.ProductsMore)
		}
		sb.WriteString("\n")
	}
	if len(s.VendorIDs) > 0 {
		sb.WriteString("vendor_ids: " + strings.Join(s.VendorIDs, ",") + "\n")
	}
	return sb.String()
}

// JSON renders the summary as one object.
func (s CVESummary) JSON() string {
	c := Curated{{"cve_id", s.CVEID}, {"detected", s.Detected}, {"hits", s.Hits}}
	if len(s.Products) > 0 {
		c = append(c, Field{"products", s.Products})
	}
	if s.ProductsMore > 0 {
		c = append(c, Field{"products_more", s.ProductsMore})
	}
	if len(s.VendorIDs) > 0 {
		c = append(c, Field{"vendor_ids", s.VendorIDs})
	}
	return c.JSON()
}
