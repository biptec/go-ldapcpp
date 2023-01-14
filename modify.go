package ldapcpp

// #include <ldap.h>
import "C"

// Change operation choices
const (
	AddAttribute     = C.LDAP_MOD_ADD
	DeleteAttribute  = C.LDAP_MOD_DELETE
	ReplaceAttribute = C.LDAP_MOD_REPLACE
)

// Modify performs the ModifyRequest
func (l *Conn) Modify(req *ModifyRequest) error {
	for _, change := range req.Changes {
		if err := l.modifyChange(req.DN, change.Operation, change.Modification.Type, change.Modification.Vals); err != nil {
			return err
		}
	}

	return nil
}

func (l *Conn) modifyChange(dn string, mod_op uint, attr string, vals []string) (err error) {
	defer Recover(&err)

	cVals := NewStringVector()
	defer DeleteStringVector(cVals)

	for _, val := range vals {
		cVals.Add(val)
	}

	l.client.Modify(dn, int(mod_op), attr, cVals)

	return nil
}

// PartialAttribute for a ModifyRequest as defined in https://tools.ietf.org/html/rfc4511
type PartialAttribute struct {
	// Type is the type of the partial attribute
	Type string
	// Vals are the values of the partial attribute
	Vals []string
}

// Change for a ModifyRequest as defined in https://tools.ietf.org/html/rfc4511
type Change struct {
	// Operation is the type of change to be made
	Operation uint
	// Modification is the attribute to be modified
	Modification PartialAttribute
}

// ModifyRequest as defined in https://tools.ietf.org/html/rfc4511
type ModifyRequest struct {
	// DN is the distinguishedName of the directory entry to modify
	DN string
	// Changes contain the attributes to modify
	Changes []Change
}

// Add appends the given attribute to the list of changes to be made
func (req *ModifyRequest) Add(attrType string, attrVals []string) {
	req.appendChange(AddAttribute, attrType, attrVals)
}

// Delete appends the given attribute to the list of changes to be made
func (req *ModifyRequest) Delete(attrType string, attrVals []string) {
	req.appendChange(DeleteAttribute, attrType, attrVals)
}

// Replace appends the given attribute to the list of changes to be made
func (req *ModifyRequest) Replace(attrType string, attrVals []string) {
	req.appendChange(ReplaceAttribute, attrType, attrVals)
}

func (req *ModifyRequest) appendChange(operation uint, attrType string, attrVals []string) {
	req.Changes = append(req.Changes, Change{operation, PartialAttribute{Type: attrType, Vals: attrVals}})
}

// NewModifyRequest creates a modify request for the given DN
func NewModifyRequest(dn string) *ModifyRequest {
	return &ModifyRequest{
		DN: dn,
	}
}
