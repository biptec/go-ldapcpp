package ldapcpp

// #cgo CPPFLAGS: -Isrc -DOPENLDAP -DKRB5 -Wno-deprecated
// #cgo LDFLAGS: -Lbuild -lclient -lstdc++ -lldap -lsasl2 -lstdc++ -llber -lresolv -lkrb5
import "C"

var logger Logger

// SetLogger sets logger
func SetLogger(l Logger) {
	logger = l
}
