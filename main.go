package main

import (
	backend "backend/packages"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

func main() {
	// the handler to verify access tokens
	jwtMiddleware, _ := backend.Middleware()

	r := mux.NewRouter()
	r.Handle("/list", jwtMiddleware.Handler(backend.GetList)).Methods("GET")
	r.Handle("/list/add", jwtMiddleware.Handler(backend.AddTask)).Methods("POST")
	r.Handle("/list/delete/{id}", jwtMiddleware.Handler(backend.DeleteTask)).Methods("DELETE")
	r.Handle("/list/edit/{id}", jwtMiddleware.Handler(backend.EditTask)).Methods("PUT")
	r.Handle("/list/done/{id}", jwtMiddleware.Handler(backend.DoneTask)).Methods("PUT")

	// for handling CORS
	c := cors.New(cors.Options{
		// Only add 1 value to allowed origins. Only the first one works. "*" is no exception.
		AllowedOrigins:   []string{"https://YOUR-FRONTEND-URL/"},
		AllowedMethods:   []string{"GET", "DELETE", "POST", "PUT", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Origin", "Accept", "Authorization"},
		AllowCredentials: true,
	})

	// if deployed, looks for port in the environment and runs on it. Otherwise, runs locally on port 8000
	port, ok := os.LookupEnv("PORT")
	if !ok {
		port = "8000"
	}

	// apply the CORS specification on the request, and add relevant CORS headers as necessary
	handler := c.Handler(r)
	log.Println("Listening on port " + port + "...")
	// run on the designated port
	log.Fatal(http.ListenAndServe(":"+port, handler))
}
