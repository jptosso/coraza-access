package main

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/jptosso/coraza-waf/v2"
	"github.com/jptosso/coraza-waf/v2/seclang"
	"github.com/jptosso/coraza-waf/v2/types/variables"
)

const (
	httpStatusBlocked int = 403
	httpStatusError   int = 401
)

func main() {
	waf := coraza.NewWaf()
	waf.SetErrorLogCb(func(mr coraza.MatchedRule) {
		fmt.Printf("Error: %s\n", mr.ErrorLog(500))
	})
	p, _ := seclang.NewParser(waf)
	if err := p.FromString(`SecRule REQUEST_URI "/block" "id:1,deny,status:500,phase:1,log,msg:'Blocked'"`); err != nil {
		panic(err)
	}
	fmt.Println("Starting POC")
	if err := http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("New transaction request")
		id := r.Header.Get("X-Coraza-ID")
		uri := r.Header.Get("X-Coraza-URL")
		if id == "" {
			http.Error(w, "X-Coraza-ID cannot be empty", httpStatusError)
			fmt.Println("X-Coraza-ID cannot be empty")
			return
		}
		if uri == "" {
			http.Error(w, "X-Coraza-URL cannot be empty", httpStatusError)
			fmt.Println("X-Coraza-URL cannot be empty")
		}
		u, err := url.Parse(uri)
		if err != nil {
			http.Error(w, err.Error(), httpStatusError)
			fmt.Println(err.Error())
		}
		*r.URL = *u

		delHeaders := []string{"X-Coraza-ID"}
		for _, h := range delHeaders {
			r.Header.Del(h)
		}
		tx := waf.NewTransaction()
		defer func() {
			tx.ProcessLogging()
			if err := tx.Clean(); err != nil {
				fmt.Println(err)
			}
		}()
		tx.ID = id
		tx.GetCollection(variables.UniqueID).SetIndex("", 0, id)
		if it, err := tx.ProcessRequest(r); err != nil {
			http.Error(w, err.Error(), httpStatusError)
			fmt.Println("Request error:", err)
		} else if it != nil {
			w.WriteHeader(httpStatusBlocked)
			fmt.Fprint(w, "blocked")
			fmt.Println("Request blocked")
		}
		if _, err := w.Write([]byte("ok")); err != nil {
			fmt.Println(err)
			fmt.Println("Response error")
			return
		}
		fmt.Printf("Transaction %s ok\n", id)
	})); err != nil {
		panic(err)
	}
}
