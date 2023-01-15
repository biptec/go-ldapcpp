package ldapcpp

import "C"

import (
	"crypto/tls"
	"net"
	"net/url"
	"sync"
	"time"
)

// DefaultTimeout is a package-level variable that sets the timeout value
// used for the Dial and DialTLS methods.
//
// WARNING: since this is a package-level variable, setting this value from
// multiple places will probably result in undesired behaviour.
var DefaultTimeout = 60 * time.Second

// DialOpt configures DialContext.
type DialOpt func(*DialContext)

// DialContext contains necessary parameters to dial the given ldap URL.
type DialContext struct {
	dialer    *net.Dialer
	tlsConfig *tls.Config
}

// Conn represents an LDAP Connection
type Conn struct {
	sync.Mutex

	client Client
	addr   string

	netTimeout int
	timeLimit  int
}

// Close closes the connection.
func (conn *Conn) Close() {
	DeleteClient(conn.client)
}

// StartTLS sends the command to start a TLS session and then creates a new TLS Client
func (conn *Conn) StartTLS(config *tls.Config) error {
	return nil
}

// GSSAPIBind performs the GSSAPI SASL bind using the provided GSSAPI client.
func (conn *Conn) GSSAPIBind(realm, keytab string) (err error) {
	defer Recover(&err)

	params := NewClientConnParams()
	defer DeleteClientConnParams(params)

	params.SetDomain(realm)
	params.SetNettimeout(conn.netTimeout)
	params.SetTimelimit(conn.timeLimit)
	params.SetSecured(true)
	params.SetUse_gssapi(true)
	params.SetUse_tls(false)
	params.SetUse_ldaps(false)

	uries := NewStringVector()
	defer DeleteStringVector(uries)

	uries.Add(conn.addr)
	params.SetUries(uries)

	conn.client.Bind(params)

	return nil
}

// DialURL connects to the given ldap URL.
// The following schemas are supported: ldap://, ldaps://, ldapi://,
// and cldap:// (RFC1798, deprecated but used by Active Directory).
// On success a new Conn for the connection is returned.
func DialURL(addr string, opts ...DialOpt) (*Conn, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}

	var dc DialContext
	for _, opt := range opts {
		opt(&dc)
	}
	if dc.dialer == nil {
		dc.dialer = &net.Dialer{Timeout: DefaultTimeout}
	}

	client := NewClient()
	if logger != nil {
		client.SetLogger(NewDirectorClientLogger(logger))
	}

	return &Conn{
		client:     client,
		addr:       u.Host,
		netTimeout: int(dc.dialer.Timeout.Seconds()),
		timeLimit:  -1,
	}, nil
}
