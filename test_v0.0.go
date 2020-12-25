package main

import (
	"./handler"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

func main() {
	router := mux.NewRouter().StrictSlash(true)
	sub := router.PathPrefix("/api").Subrouter()

	sub.Methods("GET").Path("/ping_pong").HandlerFunc(handler.PingPong2)

	log.Fatal(http.ListenAndServe(":3000", router))
}
