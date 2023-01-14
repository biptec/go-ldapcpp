package ldapcpp

// #cgo CPPFLAGS: -Isrc -DOPENLDAP -DKRB5 -Wno-deprecated
// #cgo LDFLAGS: -Lbuild -lclient -lstdc++ -lldap -lsasl2 -lstdc++ -llber -lresolv -lkrb5
// #include <ldap.h>
import "C"

func vector2slice(vector StringVector) []string {
	result := make([]string, vector.Size())
	for i := 0; i < int(vector.Size()); i++ {
		result[i] = vector.Get(i)
	}
	return result
}
