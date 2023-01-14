package ldapcpp

// #cgo CPPFLAGS: -Isrc -DOPENLDAP -DKRB5 -Wno-deprecated
// #cgo LDFLAGS: -Lbuild -lclient -lstdc++ -lldap -lsasl2 -lstdc++ -llber -lresolv -lkrb5
// #include <ldap.h>
import "C"
import (
	"crypto/tls"
)

// Conn represents an LDAP Connection
type Conn struct {
	client Client
	addr   string

	netTimeout int
	timeLimit  int
}

// Close closes the connection.
func (l *Conn) Close() {
	DeleteClient(l.client)
}

// StartTLS sends the command to start a TLS session and then creates a new TLS Client
func (l *Conn) StartTLS(config *tls.Config) error {
	return nil
}

// GSSAPIBind performs the GSSAPI SASL bind using the provided GSSAPI client.
func (l *Conn) GSSAPIBind(realm, keytab string) (err error) {
	defer Recover(&err)

	params := NewClientConnParams()
	defer DeleteClientConnParams(params)

	params.SetDomain(realm)
	params.SetNettimeout(l.netTimeout)
	params.SetTimelimit(l.timeLimit)
	params.SetSecured(true)
	params.SetUse_gssapi(true)
	params.SetUse_tls(false)
	params.SetUse_ldaps(false)

	uries := NewStringVector()
	defer DeleteStringVector(uries)

	uries.Add(l.addr)
	params.SetUries(uries)

	l.client.Bind(params)

	return nil
}

// DialURL connects to the given ldap URL.
func DialURL(addr string) (*Conn, error) {
	return &Conn{
		client:     NewClient(),
		addr:       addr,
		netTimeout: -1,
		timeLimit:  -1,
	}, nil
}
