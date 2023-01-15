package ldapcpp

// ModifyDNRequest holds the request to modify a DN
type ModifyDNRequest struct {
	DN           string
	NewRDN       string
	DeleteOldRDN bool
	NewSuperior  string
}

// NewModifyDNRequest creates a new request which can be passed to ModifyDN().
//
// To move an object in the tree, set the "newSup" to the new parent entry DN. Use an
// empty string for just changing the object's RDN.
//
// For moving the object without renaming, the "rdn" must be the first
// RDN of the given DN.
//
// A call like
//
//	mdnReq := NewModifyDNRequest("uid=someone,dc=example,dc=org", "uid=newname", true, "")
//
// will setup the request to just rename uid=someone,dc=example,dc=org to
// uid=newname,dc=example,dc=org.
func NewModifyDNRequest(dn string, rdn string, delOld bool, newSup string) *ModifyDNRequest {
	return &ModifyDNRequest{
		DN:           dn,
		NewRDN:       rdn,
		DeleteOldRDN: delOld,
		NewSuperior:  newSup,
	}
}

// NewModifyDNWithControlsRequest creates a new request which can be passed to ModifyDN()
// and also allows setting LDAP request controls.
//
// Refer NewModifyDNRequest for other parameters
func NewModifyDNWithControlsRequest(dn string, rdn string, delOld bool, newSup string) *ModifyDNRequest {
	return &ModifyDNRequest{
		DN:           dn,
		NewRDN:       rdn,
		DeleteOldRDN: delOld,
		NewSuperior:  newSup,
	}
}

// ModifyDN renames the given DN and optionally move to another base (when the "newSup" argument
// to NewModifyDNRequest() is not "").
func (conn *Conn) ModifyDN(req *ModifyDNRequest) (err error) {
	conn.Lock()
	defer conn.Unlock()

	defer Recover(&err)

	var deleteOldRDN int
	if req.DeleteOldRDN {
		deleteOldRDN = 1
	}

	conn.client.ModifyDN(req.DN, req.NewRDN, req.NewSuperior, deleteOldRDN)

	return nil
}
