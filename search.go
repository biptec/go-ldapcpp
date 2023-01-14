package ldapcpp

// #include <ldap.h>
import "C"

import (
	"fmt"
	"strings"
)

// scope choices
const (
	ScopeBaseObject   = C.LDAP_SCOPE_BASE
	ScopeSingleLevel  = C.LDAP_SCOPE_ONELEVEL
	ScopeWholeSubtree = C.LDAP_SCOPE_SUBTREE
)

// Search performs the given search request
func (l *Conn) Search(req *SearchRequest) (res *SearchResult, err error) {
	defer Recover(&err)

	vector := l.client.SearchDN(req.BaseDN, req.Filter, req.Scope)
	defer DeleteStringVector(vector)
	dns := vector2slice(vector)

	cAttrs := NewStringVector()
	defer DeleteStringVector(cAttrs)

	if len(req.Attributes) == 0 {
		cAttrs.Add("*")
	} else {
		for _, attr := range req.Attributes {
			cAttrs.Add(attr)
		}
	}

	res = &SearchResult{}

	for _, dn := range dns {
		cmap := l.client.GetObjectAttributes(dn, cAttrs)
		defer DeleteString_VectorString_Map(cmap)

		var attrs []*EntryAttribute

		keys := cmap.Keys()
		for i := 0; i < int(keys.Size()); i++ {
			name := keys.Get(i)
			values := cmap.Get(name)

			attr := NewEntryAttribute(name, vector2slice(values))
			attrs = append(attrs, attr)
		}

		entry := NewEntry(dn, attrs)
		res.Entries = append(res.Entries, entry)
	}

	return res, nil
}

func NewEntry(dn string, attrs []*EntryAttribute) *Entry {
	return &Entry{
		DN:         dn,
		Attributes: attrs,
	}
}

// Entry represents a single search result entry
type Entry struct {
	// DN is the distinguished name of the entry
	DN string
	// Attributes are the returned attributes for the entry
	Attributes []*EntryAttribute
}

// GetAttributeValues returns the values for the named attribute, or an empty list
func (e *Entry) GetAttributeValues(attribute string) []string {
	for _, attr := range e.Attributes {
		if attr.Name == attribute {
			return attr.Values
		}
	}
	return []string{}
}

// GetEqualFoldAttributeValues returns the values for the named attribute, or an
// empty list. Attribute matching is done with strings.EqualFold.
func (e *Entry) GetEqualFoldAttributeValues(attribute string) []string {
	for _, attr := range e.Attributes {
		if strings.EqualFold(attribute, attr.Name) {
			return attr.Values
		}
	}
	return []string{}
}

// GetRawAttributeValues returns the byte values for the named attribute, or an empty list
func (e *Entry) GetRawAttributeValues(attribute string) [][]byte {
	for _, attr := range e.Attributes {
		if attr.Name == attribute {
			return attr.ByteValues
		}
	}
	return [][]byte{}
}

// GetEqualFoldRawAttributeValues returns the byte values for the named attribute, or an empty list
func (e *Entry) GetEqualFoldRawAttributeValues(attribute string) [][]byte {
	for _, attr := range e.Attributes {
		if strings.EqualFold(attr.Name, attribute) {
			return attr.ByteValues
		}
	}
	return [][]byte{}
}

// GetAttributeValue returns the first value for the named attribute, or ""
func (e *Entry) GetAttributeValue(attribute string) string {
	values := e.GetAttributeValues(attribute)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// GetEqualFoldAttributeValue returns the first value for the named attribute, or "".
// Attribute comparison is done with strings.EqualFold.
func (e *Entry) GetEqualFoldAttributeValue(attribute string) string {
	values := e.GetEqualFoldAttributeValues(attribute)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// GetRawAttributeValue returns the first value for the named attribute, or an empty slice
func (e *Entry) GetRawAttributeValue(attribute string) []byte {
	values := e.GetRawAttributeValues(attribute)
	if len(values) == 0 {
		return []byte{}
	}
	return values[0]
}

// GetEqualFoldRawAttributeValue returns the first value for the named attribute, or an empty slice
func (e *Entry) GetEqualFoldRawAttributeValue(attribute string) []byte {
	values := e.GetEqualFoldRawAttributeValues(attribute)
	if len(values) == 0 {
		return []byte{}
	}
	return values[0]
}

// Print outputs a human-readable description
func (e *Entry) Print() {
	fmt.Printf("DN: %s\n", e.DN)
	for _, attr := range e.Attributes {
		attr.Print()
	}
}

// PrettyPrint outputs a human-readable description indenting
func (e *Entry) PrettyPrint(indent int) {
	fmt.Printf("%sDN: %s\n", strings.Repeat(" ", indent), e.DN)
	for _, attr := range e.Attributes {
		attr.PrettyPrint(indent + 2)
	}
}

// NewEntryAttribute returns a new EntryAttribute with the desired key-value pair
func NewEntryAttribute(name string, values []string) *EntryAttribute {
	var bytes [][]byte
	for _, value := range values {
		bytes = append(bytes, []byte(value))
	}
	return &EntryAttribute{
		Name:       name,
		Values:     values,
		ByteValues: bytes,
	}
}

// EntryAttribute holds a single attribute
type EntryAttribute struct {
	// Name is the name of the attribute
	Name string
	// Values contain the string values of the attribute
	Values []string
	// ByteValues contain the raw values of the attribute
	ByteValues [][]byte
}

// Print outputs a human-readable description
func (e *EntryAttribute) Print() {
	fmt.Printf("%s: %s\n", e.Name, e.Values)
}

// PrettyPrint outputs a human-readable description with indenting
func (e *EntryAttribute) PrettyPrint(indent int) {
	fmt.Printf("%s%s: %s\n", strings.Repeat(" ", indent), e.Name, e.Values)
}

// SearchResult holds the server's response to a search request
type SearchResult struct {
	// Entries are the returned entries
	Entries []*Entry
}

// Print outputs a human-readable description
func (s *SearchResult) Print() {
	for _, entry := range s.Entries {
		entry.Print()
	}
}

// PrettyPrint outputs a human-readable description with indenting
func (s *SearchResult) PrettyPrint(indent int) {
	for _, entry := range s.Entries {
		entry.PrettyPrint(indent)
	}
}

// SearchRequest represents a search request to send to the server
type SearchRequest struct {
	BaseDN     string
	Scope      int
	Filter     string
	Attributes []string
}

// NewSearchRequest creates a new search request
func NewSearchRequest(baseDN, filter string, scope int, attrs []string) *SearchRequest {
	return &SearchRequest{
		BaseDN:     baseDN,
		Scope:      scope,
		Filter:     filter,
		Attributes: attrs,
	}
}
