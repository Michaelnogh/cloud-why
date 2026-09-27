package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Policy language versions (the Version element, not managed policy versions).
const (
	version2012 = "2012-10-17"
	version2008 = "2008-10-17"
)

// policy is a parsed and validated IAM identity-based policy document.
type policy struct {
	version    string // "" when the Version element is absent
	single     bool   // Statement is one object rather than an array
	statements []statement
}

type statement struct {
	index        int
	sid          string
	effect       string // "Allow" or "Deny"
	notAction    bool
	actions      []string
	notResource  bool
	resources    []resourcePattern
	hasCondition bool
}

// location returns the JSON Pointer of the statement in the document.
func (p *policy) location(s statement) string {
	if p.single {
		return "/Statement"
	}
	return fmt.Sprintf("/Statement/%d", s.index)
}

var (
	topLevelKeys  = []string{"Id", "Statement", "Version"}
	statementKeys = []string{"Action", "Condition", "Effect", "NotAction", "NotResource", "Resource", "Sid"}
)

// parsePolicy validates a normalized document against the IAM identity-based
// policy grammar. Any violation is an input error: AWS validates stored
// policies, so a violation means the snapshot is broken.
func parsePolicy(doc []byte) (*policy, error) {
	// encoding/json keeps the last of duplicate keys silently; which value
	// AWS would use is not defined, so duplicates are rejected.
	if err := noDuplicateKeys(doc); err != nil {
		return nil, fmt.Errorf("policy document: %w", err)
	}
	top, err := object(doc)
	if err != nil {
		return nil, fmt.Errorf("policy document: %w", err)
	}
	if err := allowedKeys(top, topLevelKeys, "policy"); err != nil {
		return nil, err
	}

	p := &policy{}
	if raw, ok := top["Version"]; ok {
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, errors.New("Version must be a string")
		}
		if v != version2012 && v != version2008 {
			return nil, fmt.Errorf("unsupported Version %q", v)
		}
		p.version = v
	}
	if raw, ok := top["Id"]; ok {
		var id string
		if err := json.Unmarshal(raw, &id); err != nil {
			return nil, errors.New("Id must be a string")
		}
	}

	raw, ok := top["Statement"]
	if !ok {
		return nil, errors.New("missing Statement")
	}
	var items []json.RawMessage
	switch firstByte(raw) {
	case '{':
		p.single = true
		items = []json.RawMessage{raw}
	case '[':
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, fmt.Errorf("Statement: %w", err)
		}
		if len(items) == 0 {
			return nil, errors.New("Statement must not be empty")
		}
	default:
		return nil, errors.New("Statement must be an object or an array of objects")
	}

	variables := p.version == version2012
	for i, item := range items {
		s, err := parseStatement(item, variables)
		if err != nil {
			if p.single {
				return nil, fmt.Errorf("/Statement: %w", err)
			}
			return nil, fmt.Errorf("/Statement/%d: %w", i, err)
		}
		s.index = i
		p.statements = append(p.statements, s)
	}
	return p, nil
}

func parseStatement(raw json.RawMessage, variables bool) (statement, error) {
	var s statement
	m, err := object(raw)
	if err != nil {
		return s, err
	}
	if _, ok := m["Principal"]; ok {
		return s, errors.New("Principal is not valid in an identity-based policy")
	}
	if _, ok := m["NotPrincipal"]; ok {
		return s, errors.New("NotPrincipal is not valid in an identity-based policy")
	}
	if err := allowedKeys(m, statementKeys, "statement"); err != nil {
		return s, err
	}

	if raw, ok := m["Sid"]; ok {
		if err := json.Unmarshal(raw, &s.sid); err != nil {
			return s, errors.New("Sid must be a string")
		}
	}

	raw, ok := m["Effect"]
	if !ok {
		return s, errors.New("missing Effect")
	}
	if err := json.Unmarshal(raw, &s.effect); err != nil || (s.effect != "Allow" && s.effect != "Deny") {
		return s, errors.New(`Effect must be exactly "Allow" or "Deny"`)
	}

	name, values, err := exactlyOne(m, "Action", "NotAction")
	if err != nil {
		return s, err
	}
	for _, v := range values {
		if v != "*" && !strings.Contains(v, ":") {
			return s, fmt.Errorf("%s value %q must be \"*\" or service:action", name, v)
		}
	}
	s.notAction = name == "NotAction"
	s.actions = values

	name, values, err = exactlyOne(m, "Resource", "NotResource")
	if err != nil {
		return s, err
	}
	s.notResource = name == "NotResource"
	for _, v := range values {
		rp, err := compileResource(v, variables)
		if err != nil {
			return s, fmt.Errorf("%s: %w", name, err)
		}
		s.resources = append(s.resources, rp)
	}

	if raw, ok := m["Condition"]; ok {
		if firstByte(raw) != '{' {
			return s, errors.New("Condition must be an object")
		}
		s.hasCondition = true
	}
	return s, nil
}

// exactlyOne returns the element name and string values of whichever of a or
// b is present. Exactly one must be present.
func exactlyOne(m map[string]json.RawMessage, a, b string) (string, []string, error) {
	ra, okA := m[a]
	rb, okB := m[b]
	switch {
	case okA && okB:
		return "", nil, fmt.Errorf("statement must not contain both %s and %s", a, b)
	case !okA && !okB:
		return "", nil, fmt.Errorf("statement must contain %s or %s", a, b)
	case okA:
		v, err := stringOrList(ra, a)
		return a, v, err
	default:
		v, err := stringOrList(rb, b)
		return b, v, err
	}
}

func stringOrList(raw json.RawMessage, name string) ([]string, error) {
	switch firstByte(raw) {
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return []string{s}, nil
	case '[':
		var l []string
		if err := json.Unmarshal(raw, &l); err != nil {
			return nil, fmt.Errorf("%s must be a string or an array of strings", name)
		}
		if len(l) == 0 {
			return nil, fmt.Errorf("%s must not be empty", name)
		}
		return l, nil
	default:
		return nil, fmt.Errorf("%s must be a string or an array of strings", name)
	}
}

func object(raw []byte) (map[string]json.RawMessage, error) {
	if firstByte(raw) != '{' {
		return nil, errors.New("must be a JSON object")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// allowedKeys rejects unknown keys, reporting the first in sorted order so
// errors are deterministic.
func allowedKeys(m map[string]json.RawMessage, allowed []string, what string) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if !slices.Contains(allowed, k) {
			return fmt.Errorf("unknown %s element %q", what, k)
		}
	}
	return nil
}

// noDuplicateKeys reports the first object key that appears twice in the
// same JSON object, at any depth.
func noDuplicateKeys(doc []byte) error {
	dec := json.NewDecoder(bytes.NewReader(doc))
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				k := kt.(string)
				if seen[k] {
					return fmt.Errorf("duplicate key %q", k)
				}
				seen[k] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token() // '}'
			return err
		case json.Delim('['):
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token() // ']'
			return err
		}
		return nil
	}
	return walk()
}

func firstByte(b []byte) byte {
	b = bytes.TrimLeft(b, " \t\r\n")
	if len(b) == 0 {
		return 0
	}
	return b[0]
}
