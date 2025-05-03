package main

import (
	"auth-server/config"
	"auth-server/handlers"
	"auth-server/services"
	"context"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	config.InitLogger()
	r := mux.NewRouter()
	api := r.PathPrefix("/auth-server").Subrouter()

	cache := config.NewRedisClient("localhost:6379", "Redis2019!", 0)

	ctx := context.WithValue(context.Background(), "logger", config.Log)
	ctx = context.WithValue(ctx, "cache", cache)

	authServices := services.NewAuthService(ctx)
	var handler handlers.AuthHandlerInterface = handlers.NewAuthHandler(ctx, authServices)
	api.HandleFunc("/authorization", handler.WithContext(ctx, handler.AuthorizationHandler)).Methods("POST")
	api.HandleFunc("/login", handler.WithContext(ctx, handler.LoginHandler)).Methods("POST")
	api.HandleFunc("/identity/{id}", handler.WithContext(ctx, handler.IdentityHandler)).Methods("POST")
	api.HandleFunc("/challenge/{id}", handler.WithContext(ctx, handler.ChallengeHandler)).Methods("POST")
	api.HandleFunc("/token/{id}", handler.WithContext(ctx, handler.TokenHandler)).Methods("POST")
	api.HandleFunc("/introspect", handler.WithContext(ctx, handler.IntrospectHandler)).Methods("POST")

	config.Log.Info("Auth server running on port 8080")
	config.Log.Info(http.ListenAndServe(":8080", r))

}
