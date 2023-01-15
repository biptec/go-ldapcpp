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

	if err := client.GSSAPIBind("central.biptec.test", ""); err != nil {
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

	// adclient.New()

	// params := adclient.ConnParams{
	// 	Domain: "central.biptec.test",
	// 	Uries:  []string{"ds1.central.biptec.test"},

	// 	Secured:     true,
	// 	UseGSSAPI:   true,
	// 	UseLDAPS:    false,
	// 	UseStartTLS: false,
	// 	Nettimeout:  -1,
	// 	Timelimit:   -1,
	// }

	// err := adclient.Bind(params)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// defer adclient.Delete()

	// fmt.Printf("Binded to '%+v'\n\n", adclient.BindedUri())

	// dns, err := adclient.SearchDN("uid=admin,cn=users,cn=accounts,dc=central,dc=biptec,dc=test", "(objectclass=*)", 2)
	// if err != nil {
	// 	fmt.Println(err)
	// }

	// for _, dn := range dns {
	// 	fmt.Printf("[%s] DN: %s\n", time.Now().Format("2006-01-02T 15:04:05"), dn)
	// 	// values, err := adclient.GetObjectAttributes(dn)
	// 	// if err != nil {
	// 	// 	fmt.Println(err)
	// 	// }

	// 	// for key, value := range values {
	// 	// 	if key == "ipaNTHash" {
	// 	// 		value := base64.StdEncoding.EncodeToString([]byte(value[0]))
	// 	// 		fmt.Println(key, value)
	// 	// 	} else {
	// 	// 		fmt.Println(key, value)
	// 	// 	}
	// 	// }
	// }

	// // if dirty_env, err := adclient.IfDNExists(TestOU); err != nil {
	// // 	fmt.Println(err)
	// // } else if dirty_env {
	// // 	fmt.Printf("'%+v' exists, remove it before testing\n", TestOU)
	// // } else {
	// // 	ret = m.Run()
	// // }

	fmt.Println("\n-------------------------", "lab")
}
