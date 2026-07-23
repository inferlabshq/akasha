package classifier

import "strings"

type Result struct {
	Sensitive bool   `json:"sensitive"`
	Category  string `json:"category,omitempty"`
	Risk      string `json:"risk,omitempty"`
	Value     string `json:"value,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type Classifier struct {
	patterns []Pattern
	extra    []Pattern
}

func New(extraPatterns []Pattern) *Classifier {
	return &Classifier{
		patterns: builtinPatterns,
		extra:    extraPatterns,
	}
}

// Classify returns the first sensitive match found in content, or a non-sensitive result.
func (c *Classifier) Classify(toolName, content string) Result {
	all := append(c.patterns, c.extra...)
	for _, p := range all {
		if loc := p.Re.FindStringIndex(content); loc != nil {
			matched := content[loc[0]:loc[1]]
			return Result{
				Sensitive: true,
				Category:  p.Category,
				Risk:      p.Risk,
				Value:     matched,
				Reason:    "Matched " + p.Name + " pattern",
			}
		}
	}

	// Escalate based on tool name even when content matched nothing.
	if toolName != "" {
		if risk, ok := riskyToolNames[strings.ToLower(toolName)]; ok {
			return Result{
				Sensitive: true,
				Category:  "RiskyTool",
				Risk:      risk,
				Reason:    "Tool name is on watchlist: " + toolName,
			}
		}
	}

	return Result{Sensitive: false}
}

// ClassifyAll returns every match found (used for bulk scanning).
func (c *Classifier) ClassifyAll(toolName, content string) []Result {
	var results []Result
	seen := map[string]bool{}

	all := append(c.patterns, c.extra...)
	for _, p := range all {
		locs := p.Re.FindAllStringIndex(content, -1)
		for _, loc := range locs {
			matched := content[loc[0]:loc[1]]
			key := p.Category + ":" + matched
			if seen[key] {
				continue
			}
			seen[key] = true
			results = append(results, Result{
				Sensitive: true,
				Category:  p.Category,
				Risk:      p.Risk,
				Value:     matched,
				Reason:    "Matched " + p.Name + " pattern",
			})
		}
	}

	if toolName != "" {
		if risk, ok := riskyToolNames[strings.ToLower(toolName)]; ok {
			results = append(results, Result{
				Sensitive: true,
				Category:  "RiskyTool",
				Risk:      risk,
				Reason:    "Tool name is on watchlist: " + toolName,
			})
		}
	}

	return results
}
