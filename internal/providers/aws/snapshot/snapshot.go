// Package snapshot reads the subset of an AWS GetAccountAuthorizationDetails
// response that CW-001 needs, and normalizes policy documents to JSON
// objects. It interprets no IAM policy semantics.
package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"unicode/utf8"
)

// Format describes the accepted input for provenance.
const Format = "AWS GetAccountAuthorizationDetails response (user-supplied)"

// AuthorizationDetails is the subset of the export that CW-001 reads.
// Unknown fields are ignored.
type AuthorizationDetails struct {
	UserDetailList  []UserDetail          `json:"UserDetailList"`
	GroupDetailList []GroupDetail         `json:"GroupDetailList"`
	RoleDetailList  []RoleDetail          `json:"RoleDetailList"`
	Policies        []ManagedPolicyDetail `json:"Policies"`
	IsTruncated     bool                  `json:"IsTruncated"`
}

// InlinePolicy is an inline policy entry. PolicyDocument is kept raw; use
// NormalizeDocument before interpreting it.
type InlinePolicy struct {
	PolicyName     string          `json:"PolicyName"`
	PolicyDocument json.RawMessage `json:"PolicyDocument"`
}

// AttachedPolicy is a managed policy attachment.
type AttachedPolicy struct {
	PolicyName string `json:"PolicyName"`
	PolicyArn  string `json:"PolicyArn"`
}

// PermissionsBoundary records an attached permissions boundary.
type PermissionsBoundary struct {
	PermissionsBoundaryArn string `json:"PermissionsBoundaryArn"`
}

type UserDetail struct {
	Arn                     string               `json:"Arn"`
	UserName                string               `json:"UserName"`
	UserPolicyList          []InlinePolicy       `json:"UserPolicyList"`
	AttachedManagedPolicies []AttachedPolicy     `json:"AttachedManagedPolicies"`
	GroupList               []string             `json:"GroupList"`
	PermissionsBoundary     *PermissionsBoundary `json:"PermissionsBoundary"`
}

type GroupDetail struct {
	Arn                     string           `json:"Arn"`
	GroupName               string           `json:"GroupName"`
	GroupPolicyList         []InlinePolicy   `json:"GroupPolicyList"`
	AttachedManagedPolicies []AttachedPolicy `json:"AttachedManagedPolicies"`
}

type RoleDetail struct {
	Arn                     string               `json:"Arn"`
	RoleName                string               `json:"RoleName"`
	RolePolicyList          []InlinePolicy       `json:"RolePolicyList"`
	AttachedManagedPolicies []AttachedPolicy     `json:"AttachedManagedPolicies"`
	PermissionsBoundary     *PermissionsBoundary `json:"PermissionsBoundary"`
}

type PolicyVersion struct {
	VersionId        string          `json:"VersionId"`
	IsDefaultVersion bool            `json:"IsDefaultVersion"`
	Document         json.RawMessage `json:"Document"`
}

type ManagedPolicyDetail struct {
	Arn               string          `json:"Arn"`
	PolicyName        string          `json:"PolicyName"`
	DefaultVersionId  string          `json:"DefaultVersionId"`
	PolicyVersionList []PolicyVersion `json:"PolicyVersionList"`
}

// Parse decodes an export. The top level must be a JSON object; known fields
// must have the documented JSON types.
func Parse(data []byte) (*AuthorizationDetails, error) {
	if firstByte(data) != '{' {
		return nil, errors.New("snapshot: top level must be a JSON object")
	}
	var d AuthorizationDetails
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	return &d, nil
}

// Encoding names how a policy document was stored in the snapshot.
const (
	EncodingJSONObject = "json-object"
	EncodingURLEncoded = "url-encoded"
)

// Document is a policy document normalized to a JSON object.
type Document struct {
	JSON     []byte
	Encoding string
}

// NormalizeDocument turns a raw policy document value into a JSON object.
//
// A JSON object is used as is. A JSON string is treated as RFC 3986
// percent-encoded text, as returned by GetAccountAuthorizationDetails, and is
// decoded exactly once with url.PathUnescape, which keeps '+' literal.
// url.QueryUnescape must not be used: it decodes '+' as a space.
func NormalizeDocument(raw json.RawMessage) (Document, error) {
	switch firstByte(raw) {
	case '{':
		return Document{JSON: raw, Encoding: EncodingJSONObject}, nil
	case '"':
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return Document{}, fmt.Errorf("policy document: %w", err)
		}
		decoded, err := url.PathUnescape(s)
		if err != nil {
			return Document{}, fmt.Errorf("policy document: malformed URL encoding: %w", err)
		}
		b := []byte(decoded)
		if !utf8.Valid(b) {
			return Document{}, errors.New("policy document: URL-decoded text is not valid UTF-8")
		}
		if firstByte(b) != '{' || !json.Valid(b) {
			return Document{}, errors.New("policy document: URL-decoded text is not a JSON object")
		}
		return Document{JSON: b, Encoding: EncodingURLEncoded}, nil
	case 0:
		return Document{}, errors.New("policy document: missing")
	default:
		return Document{}, errors.New("policy document: must be a JSON object or a URL-encoded JSON string")
	}
}

// firstByte returns the first non-whitespace byte, or 0 if there is none.
func firstByte(b []byte) byte {
	b = bytes.TrimLeft(b, " \t\r\n")
	if len(b) == 0 {
		return 0
	}
	return b[0]
}
