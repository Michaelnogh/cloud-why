package engine

import (
	"errors"
	"fmt"
	"strings"
)

// tokenKind is one element of a compiled wildcard pattern.
type tokenKind uint8

const (
	tokLiteral     tokenKind = iota // one exact character
	tokOneAny                       // ? in an action: any one character
	tokOneSegment                   // ? in a resource: any one character except ':'
	tokStarAny                      // * matching any characters, including ':'
	tokStarSegment                  // * matching any characters except ':'
)

type token struct {
	kind tokenKind
	r    rune
}

// matchTokens reports whether toks match all of s. It is a dynamic-programming
// glob matcher, O(len(toks) * len(s)), with no backtracking blow-up.
func matchTokens(toks []token, s []rune) bool {
	n := len(s)
	prev := make([]bool, n+1)
	prev[0] = true
	cur := make([]bool, n+1)
	for _, t := range toks {
		clear(cur)
		switch t.kind {
		case tokLiteral:
			for j := 1; j <= n; j++ {
				cur[j] = prev[j-1] && s[j-1] == t.r
			}
		case tokOneAny:
			for j := 1; j <= n; j++ {
				cur[j] = prev[j-1]
			}
		case tokOneSegment:
			for j := 1; j <= n; j++ {
				cur[j] = prev[j-1] && s[j-1] != ':'
			}
		case tokStarAny:
			cur[0] = prev[0]
			for j := 1; j <= n; j++ {
				cur[j] = prev[j] || cur[j-1]
			}
		case tokStarSegment:
			cur[0] = prev[0]
			for j := 1; j <= n; j++ {
				cur[j] = prev[j] || (cur[j-1] && s[j-1] != ':')
			}
		}
		prev, cur = cur, prev
	}
	return prev[n]
}

// matchAction reports whether an Action or NotAction pattern matches the
// request action. AWS: "The prefix and the action name are case
// insensitive." Both * and ? are wildcards; * alone matches every action.
func matchAction(pattern, action string) bool {
	var toks []token
	for _, r := range strings.ToLower(pattern) {
		switch r {
		case '*':
			toks = append(toks, token{kind: tokStarAny})
		case '?':
			toks = append(toks, token{kind: tokOneAny})
		default:
			toks = append(toks, token{kind: tokLiteral, r: r})
		}
	}
	return matchTokens(toks, []rune(strings.ToLower(action)))
}

// resourceMatch is the result of matching one resource pattern.
type resourceMatch uint8

const (
	resNoMatch resourceMatch = iota
	resMatch
	resUnresolvable
)

// resourcePattern is a compiled Resource or NotResource value.
type resourcePattern struct {
	raw          string
	any          bool     // the pattern is exactly "*"
	unresolvable []string // context-dependent policy variables, e.g. aws:username
	toks         []token
}

// rawKind classifies lexed pattern elements before compilation.
type rawKind uint8

const (
	rawChar rawKind = iota
	rawStar
	rawQuestion
	rawVar
)

type rawElem struct {
	kind  rawKind
	r     rune
	name  string // variable content for rawVar
	field int    // ARN field index (number of ':' before this element)
}

// compileResource compiles a Resource or NotResource value following the
// IAM User Guide ("Resource", "Identify AWS resources with ARNs", "Policy
// variables"). variables is true for Version 2012-10-17 documents; otherwise
// "${...}" is literal text.
func compileResource(raw string, variables bool) (resourcePattern, error) {
	p := resourcePattern{raw: raw}
	if raw == "*" {
		p.any = true
		return p, nil
	}
	if !strings.HasPrefix(raw, "arn:") {
		return p, fmt.Errorf("resource %q must be \"*\" or start with \"arn:\"", raw)
	}

	// Lex into characters, wildcards and variables, tracking the ARN field.
	var elems []rawElem
	runes := []rune(raw)
	field := 0
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if variables && r == '$' && i+1 < len(runes) && runes[i+1] == '{' {
			end := -1
			for j := i + 2; j < len(runes); j++ {
				if runes[j] == '}' {
					end = j
					break
				}
			}
			if end < 0 {
				return p, fmt.Errorf("resource %q: unterminated policy variable", raw)
			}
			elems = append(elems, rawElem{kind: rawVar, name: string(runes[i+2 : end]), field: field})
			i = end
			continue
		}
		switch r {
		case '*':
			elems = append(elems, rawElem{kind: rawStar, field: field})
		case '?':
			elems = append(elems, rawElem{kind: rawQuestion, field: field})
		default:
			elems = append(elems, rawElem{kind: rawChar, r: r, field: field})
			if r == ':' {
				field++
			}
		}
	}

	// Validate positions against the pattern as written.
	for _, e := range elems {
		if (e.kind == rawStar || e.kind == rawQuestion) && (e.field == 1 || e.field == 2) {
			return p, fmt.Errorf("resource %q: AWS does not allow a wildcard in the partition or service field", raw)
		}
		if e.kind == rawVar && e.field < 5 {
			return p, fmt.Errorf("resource %q: AWS does not allow a policy variable before the fifth colon", raw)
		}
	}

	// Incomplete ARN: AWS completes it with * in every missing field.
	for field < 5 {
		elems = append(elems, rawElem{kind: rawChar, r: ':', field: field})
		field++
		elems = append(elems, rawElem{kind: rawStar, field: field})
	}

	for i, e := range elems {
		switch e.kind {
		case rawChar:
			p.toks = append(p.toks, token{kind: tokLiteral, r: e.r})
		case rawQuestion:
			p.toks = append(p.toks, token{kind: tokOneSegment})
		case rawStar:
			// A * that is the last character of its segment can expand
			// beyond colon boundaries.
			last := i == len(elems)-1 || (elems[i+1].kind == rawChar && elems[i+1].r == ':')
			if last {
				p.toks = append(p.toks, token{kind: tokStarAny})
			} else {
				p.toks = append(p.toks, token{kind: tokStarSegment})
			}
		case rawVar:
			switch e.name {
			case "*", "?", "$":
				// Special variables with fixed literal values; the resulting
				// character is not a wildcard.
				p.toks = append(p.toks, token{kind: tokLiteral, r: rune(e.name[0])})
			default:
				p.unresolvable = append(p.unresolvable, e.name)
			}
		}
	}
	return p, nil
}

// match matches the pattern against the request resource. The request value
// "*" is literal: only the policy pattern "*" matches it.
func (p resourcePattern) match(resource string) resourceMatch {
	if p.any {
		return resMatch
	}
	if resource == "*" {
		return resNoMatch
	}
	if len(p.unresolvable) > 0 {
		return resUnresolvable
	}
	if matchTokens(p.toks, []rune(resource)) {
		return resMatch
	}
	return resNoMatch
}

var errBadAction = errors.New("action must be service:Name (letters, digits and hyphen in the service prefix, letters and digits in the name, no wildcards)")

// validateAction checks the question action format.
func validateAction(a string) error {
	svc, name, ok := strings.Cut(a, ":")
	if !ok || svc == "" || name == "" {
		return errBadAction
	}
	for _, r := range svc {
		if !(isAlnum(r) || r == '-') {
			return errBadAction
		}
	}
	for _, r := range name {
		if !isAlnum(r) {
			return errBadAction
		}
	}
	return nil
}

func isAlnum(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}
