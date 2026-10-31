package detect

// Sources of a finding.
const (
	SourceNone        = "none"
	SourceName        = "name"
	SourceContent     = "content"
	SourceNameContent = "name+content"
)

// Finding is the verdict on one column or field: what kind of personal data it holds, how
// sure the bridge is, and where the evidence came from. It never carries a value.
type Finding struct {
	IsPII      bool           `json:"is_pii"`
	Category   Category       `json:"category,omitempty"`
	PDP        string         `json:"pdp_category,omitempty"`
	Confidence float64        `json:"confidence"`
	Source     string         `json:"source"`
	Content    *ContentResult `json:"content,omitempty"`
	// Shadow is true when the values hold personal data that the name does not reveal.
	Shadow bool `json:"shadow,omitempty"`
}

// Combine merges the verdict on a name with the verdict on sampled values (content may be
// nil when sampling is off).
func Combine(name string, content *ContentResult) Finding {
	nm, nameOK := ClassifyName(name)
	f := Finding{Source: SourceNone, Content: content}
	contentOK := content != nil && content.Detected
	switch {
	case nameOK && contentOK && nm.Category == content.Category:
		f.Category = nm.Category
		f.Confidence = round2(clamp1(maxf(nm.Confidence, content.Confidence) + 0.05))
		f.Source = SourceNameContent
	case contentOK:
		// The data wins over the naming: a "notes" column full of phone numbers holds
		// phone numbers, whatever it is called.
		f.Category = content.Category
		f.Confidence = content.Confidence
		f.Source = SourceContent
		f.Shadow = !nameOK
		if nameOK {
			f.Source = SourceNameContent
		}
	case nameOK:
		f.Category = nm.Category
		f.Confidence = nm.Confidence
		f.Source = SourceName
	}
	if f.Category != "" {
		f.IsPII = true
		f.PDP = PDPOf(f.Category)
	}
	return f
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func clamp1(f float64) float64 {
	if f > 1 {
		return 1
	}
	return f
}
