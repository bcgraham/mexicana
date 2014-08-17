package main

import (
	"fmt"
	"net/http"
	"net/rpc"
)

func main() {
	http.HandleFunc("/", simplify)
	http.ListenAndServe(":8083", nil)
}

func simplify(w http.ResponseWriter, r *http.Request) {
	client, err := rpc.Dial("unix", "/tmp/mexicana.sock")
	var willAlert bool
	a := &alert{"Q47", 2}
	err = client.Call("AlertRequestListener.RequestNew", a, &willAlert)
	if err != nil {
		fmt.Fprintf(w, "There was a problem making the request. No alert will be provided. Error: %v", err)
		return
	}
	if !willAlert {
		fmt.Fprintf(w, "Tracker is already busy; your request for an alert is denied.")
		return
	}
	fmt.Fprintf(w, "You will be alerted when a bus is nearby.")
	return
}

type alert struct {
	line      string
	stopsAway int
}
