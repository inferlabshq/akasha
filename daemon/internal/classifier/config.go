package classifier

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/inferlabshq/akasha/daemon/internal/policy"
)

// LoadConfig reads custom patterns from a config file and returns them as
// []Pattern suitable for passing to New(). The format is intentionally tiny
// and dependency-free — one pattern per block, fields as `key: value` lines,
// blocks separated by a line starting with `-`.
//
// Example ~/.akasha/patterns.conf:
//
//   - name: Acme Employee ID
//     category: EmployeeID
//     risk: high
//     pattern: EMP-\d{6}
//
//   - name: Internal Ticket
//     category: TicketRef
//     risk: low
//     pattern: ACME-[A-Z]+-\d+
//
// Missing file is not an error — it returns nil so the daemon runs with
// built-in patterns only.
func LoadConfig(path string) ([]Pattern, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ParseConfig(string(data))
}

// ParseConfig parses the pattern config format from a string.
func ParseConfig(content string) ([]Pattern, error) {
	var patterns []Pattern
	var cur map[string]string
	lineNum := 0

	flush := func() error {
		if cur == nil {
			return nil
		}
		name := cur["name"]
		pat := cur["pattern"]
		if name == "" || pat == "" {
			return fmt.Errorf("pattern block missing name or pattern")
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return fmt.Errorf("invalid regex for %q: %w", name, err)
		}
		risk := cur["risk"]
		if risk == "" {
			risk = "medium"
		}
		// A typo here would otherwise be silent and load-bearing: an
		// unrankable risk makes every entry this pattern classifies invisible
		// to `min_risk` policy rules. Fail the config load instead.
		if !policy.ValidRisk(risk) {
			return fmt.Errorf("pattern %q: risk %q is not a known level (want one of %s)",
				name, risk, strings.Join(policy.RiskLevels(), ", "))
		}
		category := cur["category"]
		if category == "" {
			category = "Custom"
		}
		patterns = append(patterns, Pattern{
			Name:     name,
			Category: category,
			Risk:     risk,
			Re:       re,
		})
		cur = nil
		return nil
	}

	for _, raw := range strings.Split(content, "\n") {
		lineNum++
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// New block marker: "- name: ..." or just "-"
		if strings.HasPrefix(line, "-") {
			if err := flush(); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNum, err)
			}
			cur = map[string]string{}
			line = strings.TrimSpace(strings.TrimPrefix(line, "-"))
			if line == "" {
				continue
			}
		}

		if cur == nil {
			return nil, fmt.Errorf("line %d: field outside a pattern block (start with '-')", lineNum)
		}

		key, val, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("line %d: expected 'key: value'", lineNum)
		}
		cur[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}

	if err := flush(); err != nil {
		return nil, fmt.Errorf("line %d: %w", lineNum, err)
	}
	return patterns, nil
}
