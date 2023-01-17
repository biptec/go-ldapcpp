package main

import (
	"fmt"
	"log"
	"os"

	ldap "github.com/biptec/go-ldapcpp"
)

type Logger struct {
	*log.Logger
}

func (log *Logger) Debug(msg string) {
	log.Println("Debug:", msg)
}

func (log *Logger) Error(msg string) {
	log.Println("Error:", msg)
}

func main() {
	ldap.SetLogger(&Logger{
		Logger: log.New(os.Stderr, "", log.LstdFlags),
	})

	client, err := ldap.DialURL("ldap://ds1.central.biptec.test")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer client.Close()

	if err := client.GSSAPIBind("CENTRAL.BIPTEC.TEST", "/private/work/biptec/lab/krb5.keytab"); err != nil {
		fmt.Println(err)
		return
	}

	// modReq := ldap.NewModifyRequest("uid=levko.himins,cn=users,cn=accounts,dc=central,dc=biptec,dc=test")
	// modReq.Replace("sn", []string{"BurburasNew"})

	// if err := client.Modify(modReq); err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	req := ldap.NewSearchRequest("cn=users,cn=accounts,dc=central,dc=biptec,dc=test", "(objectclass=*)", ldap.ScopeWholeSubtree, []string{"cn", "sn"})
	res, err := client.Search(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	res.PrettyPrint(2)

	fmt.Println("\n-------------------------", "lab")
}
