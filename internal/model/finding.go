package model

import "time"

// Severity ranks how much a finding matters. The set is closed: a rule picks
// one of these rather than inventing its own word for "quite bad".
type Severity string

// The severities, least to most serious.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Severities lists them in the order views present them: most serious first,
// because that is the end of the list anyone reads.
var Severities = []Severity{
	SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo,
}

// Rank orders severities for sorting. An unknown value ranks below info, so a
// hand-edited database cannot push itself to the top of the list.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Valid reports whether s is one of the defined severities.
func (s Severity) Valid() bool { return s.Rank() > 0 }

// FindingStatus is where a finding sits in triage (CLAUDE.md, "Findings").
type FindingStatus string

// The triage states.
const (
	StatusNew           FindingStatus = "new"
	StatusInvestigating FindingStatus = "investigating"
	StatusAcceptedRisk  FindingStatus = "accepted_risk"
	StatusFalsePositive FindingStatus = "false_positive"
	StatusResolved      FindingStatus = "resolved"
)

// Statuses lists the triage states in the order the workflow runs.
var Statuses = []FindingStatus{
	StatusNew, StatusInvestigating, StatusAcceptedRisk, StatusFalsePositive, StatusResolved,
}

// Valid reports whether s is one of the defined statuses.
func (s FindingStatus) Valid() bool {
	for _, known := range Statuses {
		if s == known {
			return true
		}
	}
	return false
}

// Open reports whether a finding in this state still wants attention.
func (s FindingStatus) Open() bool {
	return s == StatusNew || s == StatusInvestigating
}

// Finding is one rule's observation, with the evidence that produced it.
//
// CLAUDE.md is categorical about the evidence: "Every finding carries
// evidence: capture ID, packet index, timestamp, src, dst, protocol, function
// code, and a link to the flow in the GUI. No finding without traceable
// evidence." The Evidence field is that, and the engine refuses a finding
// without it.
type Finding struct {
	// ID is derived from the rule and what the finding is about, so that
	// re-running the rules over the same project produces the same finding
	// rather than a duplicate — which is what lets triage survive a re-run.
	ID     string `json:"id"`
	RuleID string `json:"rule_id"`

	Title string `json:"title"`
	// Summary is this finding in one line: what happened, to which device.
	Summary string `json:"summary"`
	// Description is the rule's own explanation, the same for every finding
	// it raises.
	Description string `json:"description,omitempty"`

	Severity Severity `json:"severity"`
	// Technique is a MITRE ATT&CK for ICS technique id, with its name.
	Technique     string `json:"technique,omitempty"`
	TechniqueName string `json:"technique_name,omitempty"`

	Status   FindingStatus `json:"status"`
	Assignee string        `json:"assignee,omitempty"`
	Note     string        `json:"note,omitempty"`

	// Src and Dst are the endpoints as the flow views spell them: an IP, or a
	// MAC for a protocol with no IP layer.
	Src      string `json:"src,omitempty"`
	Dst      string `json:"dst,omitempty"`
	Protocol string `json:"protocol,omitempty"`

	// Count is how many observations this finding stands for. A rule that
	// fires on every write would otherwise bury the one that fires on a
	// firmware download.
	Count     int64     `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	// Evidence points at the first packet that raised it.
	Evidence Evidence `json:"evidence"`
	// Details holds whatever else the rule wants on the page, such as the
	// function code it matched or the threshold it crossed.
	Details map[string]string `json:"details,omitempty"`
}
