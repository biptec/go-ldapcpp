package ldapcpp

// #cgo CPPFLAGS: -DOPENLDAP -DKRB5 -Wno-deprecated
// #cgo LDFLAGS: -L. -lclient -lstdc++ -lldap -lsasl2 -lstdc++ -llber -lresolv -lkrb5
// #include <ldap.h>
import "C"

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	SCOPE_BASE        = C.LDAP_SCOPE_BASE
	SCOPE_BASEOBJECT  = C.LDAP_SCOPE_BASE
	SCOPE_ONELEVEL    = C.LDAP_SCOPE_ONELEVEL
	SCOPE_ONE         = C.LDAP_SCOPE_ONELEVEL
	SCOPE_SUBTREE     = C.LDAP_SCOPE_SUBTREE
	SCOPE_SUB         = C.LDAP_SCOPE_SUBTREE
	SCOPE_SUBORDINATE = C.LDAP_SCOPE_SUBORDINATE /* OpenLDAP extension */
	SCOPE_CHILDREN    = C.LDAP_SCOPE_SUBORDINATE
	SCOPE_DEFAULT     = C.LDAP_SCOPE_DEFAULT /* OpenLDAP extension */
)

type Error struct {
	msg  string
	code int
}

type ConnParams struct {
	Domain      string
	Site        string
	Uries       []string
	Binddn      string
	Bindpw      string
	Search_base string

	Secured     bool
	UseGSSAPI   bool
	UseLDAPS    bool
	UseStartTLS bool

	Nettimeout int
	Timelimit  int
}

func DefaultConnParams() (params ConnParams) {
	params.Nettimeout = -1
	params.Timelimit = -1
	params.Secured = true
	params.UseGSSAPI = false
	params.UseLDAPS = false
	params.UseStartTLS = false
	return
}

func Ldap_servers(domain string, site string) []string {
	vector := ClientGet_ldap_servers(domain, site)
	defer DeleteStringVector(vector)
	result := vector2slice(vector)
	return result
}

func Domain2dn(domain string) string {
	dn := ClientDomain2dn(domain)
	return dn
}

func (err Error) Error() string {
	return fmt.Sprintf("%v: %v", err.code, err.msg)
}

func catch(err *error) {
	if r := recover(); r != nil {
		err_splitted := strings.SplitN(r.(string), ":", 2)
		if len(err_splitted) != 2 {
			*err = Error{
				r.(string),
				-1,
			}
		} else {
			code, code_err := strconv.Atoi(err_splitted[0])
			if code_err != nil {
				code = -1
			}
			*err = Error{
				err_splitted[1],
				code,
			}
		}
	}
}

func vector2slice(vector StringVector) []string {
	result := make([]string, vector.Size())
	for i := 0; i < int(vector.Size()); i++ {
		result[i] = vector.Get(i)
	}
	return result
}

func commonStringToSlice(f func(string) StringVector, thing string) (result []string, err error) {
	defer catch(&err)
	vector := f(thing)
	defer DeleteStringVector(vector)
	result = vector2slice(vector)
	return
}

func common2StringsToSlice(f func(string, string) StringVector, thing1 string, thing2 string) (result []string, err error) {
	defer catch(&err)
	vector := f(thing1, thing2)
	defer DeleteStringVector(vector)
	result = vector2slice(vector)
	return
}

func commonStringsIntToSlice(f func(string, int) StringVector, thing1 string, thing2 int) (result []string, err error) {
	defer catch(&err)
	vector := f(thing1, thing2)
	defer DeleteStringVector(vector)
	result = vector2slice(vector)
	return
}

func commonEmptyToSlice(f func() StringVector) (result []string, err error) {
	defer catch(&err)
	vector := f()
	defer DeleteStringVector(vector)
	result = vector2slice(vector)
	return
}

var ad Client

func New() {
	ad = NewClient()
}

func Delete() {
	DeleteAdclient(ad)
}

func Login(_params ConnParams) (err error) {
	defer catch(&err)

	params := NewConnParams()
	defer DeleteConnParams(params)

	params.SetDomain(_params.Domain)
	params.SetSite(_params.Site)
	params.SetBinddn(_params.Binddn)
	params.SetBindpw(_params.Bindpw)
	params.SetSearch_base(_params.Search_base)
	params.SetSecured(_params.Secured)
	params.SetUse_gssapi(_params.UseGSSAPI)
	params.SetNettimeout(_params.Nettimeout)
	params.SetTimelimit(_params.Timelimit)
	params.SetUse_tls(_params.UseStartTLS)
	params.SetUse_ldaps(_params.UseLDAPS)

	uries := NewStringVector()
	defer DeleteStringVector(uries)
	for _, uri := range _params.Uries {
		uries.Add(uri)
	}
	params.SetUries(uries)

	ad.Login(params)
	return
}

func LoginOld(uri interface{}, user string, passwd string, sb string, secured bool) (err error) {
	defer catch(&err)

	args := DefaultConnParams()
	args.Binddn = user
	args.Bindpw = passwd
	args.Search_base = sb
	args.UseGSSAPI = secured

	switch uri.(type) {
	case string:
		args.Domain = uri.(string)
	case []string:
		args.Uries = uri.([]string)
	default:
		err = Error{
			fmt.Sprintf("unknown uri type - %#v", uri),
			-1,
		}
	}
	Login(args)
	return
}

func BindedUri() (result string) {
	return ad.Binded_uri()
}

func SearchBase() (result string) {
	return ad.Search_base()
}

func LoginMethod() (result string) {
	return ad.Login_method()
}

func BindMethod() (result string) {
	return ad.Bind_method()
}

func DeleteDN(dn string) (err error) {
	defer catch(&err)
	ad.DeleteDN(dn)
	return
}

func RenameDN(dn string, new_rdn string) (err error) {
	defer catch(&err)
	ad.RenameDN(dn, new_rdn)
	return
}

func GetObjectDN(object string) (result string, err error) {
	defer catch(&err)
	result = ad.GetObjectDN(object)
	return
}

func IfDialinUser(user string) (result bool, err error) {
	defer catch(&err)
	result = ad.IfDialinUser(user)
	return
}

func IfDNExists(args ...string) (result bool, err error) {
	defer catch(&err)
	switch len(args) {
	case 1:
		result = ad.IfDNExists(args[0])
	case 2:
		result = ad.IfDNExists(args[0], args[1])
	default:
		panic("wrong number of args for IfDNExists")
	}
	return
}

func GetObjectAttribute(object string, attribute string) (result []string, err error) {
	return common2StringsToSlice(ad.GetObjectAttribute, object, attribute)
}

func SearchDN(search_base string, filter string, scope int) (result []string, err error) {
	defer catch(&err)
	vector := ad.SearchDN(search_base, filter, scope)
	defer DeleteStringVector(vector)
	result = vector2slice(vector)
	return
}

func SetObjectAttribute(object string, attr string, values ...string) (err error) {
	if len(values) == 0 {
		err = Error{
			fmt.Sprintf("wrong number of arguments"),
			-1,
		}
	} else {
		defer catch(&err)
		cattrs := NewStringVector()
		defer DeleteStringVector(cattrs)
		for _, attr := range values {
			cattrs.Add(attr)
		}
		ad.SetObjectAttribute(object, attr, cattrs)
	}
	return
}

func ClearObjectAttribute(object string, attr string) (err error) {
	defer catch(&err)
	ad.ClearObjectAttribute(object, attr)
	return
}

func MoveObject(object string, new_container string) (err error) {
	defer catch(&err)
	ad.MoveObject(object, new_container)
	return
}

func GetObjectAttributes(object string, attrs ...string) (result map[string][]string, err error) {
	cattrs := NewStringVector()
	defer DeleteStringVector(cattrs)
	if len(attrs) == 0 {
		cattrs.Add("*")
	} else {
		for _, attr := range attrs {
			cattrs.Add(attr)
		}
	}

	result = make(map[string][]string)
	defer catch(&err)
	cmap := ad.GetObjectAttributes(object, cattrs)
	defer DeleteString_VectorString_Map(cmap)
	keys := cmap.Keys()
	for i := 0; i < int(keys.Size()); i++ {
		key := keys.Get(i)
		value := cmap.Get(key)
		result[key] = vector2slice(value)
	}
	return
}
