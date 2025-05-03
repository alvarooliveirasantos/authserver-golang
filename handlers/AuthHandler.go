package handlers

import (
	"auth-server/config"
	"auth-server/models"
	"auth-server/services"
	"context"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type AuthHandlerInterface interface {
	LoginHandler(w http.ResponseWriter, r *http.Request)
	AuthorizationHandler(w http.ResponseWriter, r *http.Request)
	WithContext(ctx context.Context, h http.HandlerFunc) http.HandlerFunc
	IdentityHandler(w http.ResponseWriter, r *http.Request)
	ChallengeHandler(w http.ResponseWriter, r *http.Request)
	TokenHandler(w http.ResponseWriter, r *http.Request)
	IntrospectHandler(w http.ResponseWriter, r *http.Request)
}
type AuthHandler struct {
	ctx          context.Context
	authServices services.AuthServiceInterface
	logger       *logrus.Logger
	cache        config.Cache
}

func NewAuthHandler(ctx context.Context, authServices services.AuthServiceInterface) *AuthHandler {
	logger := ctx.Value("logger").(*logrus.Logger)
	cache := ctx.Value("cache").(config.Cache)
	return &AuthHandler{ctx: ctx, authServices: authServices, logger: logger, cache: cache}
}

func (h *AuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var creds services.Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	h.logger.Info("Login attempt with username: ", creds.Username)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	token, err := h.authServices.Authenticate(r.Context(), creds)
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}
func (h *AuthHandler) AuthorizationHandler(w http.ResponseWriter, r *http.Request) {
	var authorizationModel models.AuthorizationRequest
	err := json.NewDecoder(r.Body).Decode(&authorizationModel)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	authorizationModel.User_agent = r.UserAgent()
	// h.logger.Info("Authorize request", authorizationModel)
	result, err := h.authServices.Authorization(r.Context(), authorizationModel)
	if err != nil {
		http.Error(w, "Authorization failed", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)

}
func (h *AuthHandler) IdentityHandler(w http.ResponseWriter, r *http.Request) {
	var identityModel models.IdentityRequest
	err := json.NewDecoder(r.Body).Decode(&identityModel)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	vars := mux.Vars(r)
	idChallenge := vars["id"]
	h.logger.Infof("Received identity ID: %s", idChallenge)
	cache, err := h.cache.Get(r.Context(), idChallenge)
	if err != nil {
		http.Error(w, "identity not found", http.StatusNotFound)
		return
	}
	result, err := h.authServices.Identity(r.Context(), identityModel)
	if err != nil {
		http.Error(w, "identity failed", http.StatusUnauthorized)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(cache))
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		http.Error(w, "Failed to marshal response to JSON", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resultJSON)
}

func (h *AuthHandler) ChallengeHandler(w http.ResponseWriter, r *http.Request) {
	var challengeModel models.ChallengeRequest
	err := json.NewDecoder(r.Body).Decode(&challengeModel)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	vars := mux.Vars(r)
	idChallenge := vars["id"]
	h.logger.Infof("Received challenge ID: %s", idChallenge)
	cache, err := h.cache.Get(r.Context(), idChallenge)
	if err != nil {
		http.Error(w, "Challenge not found", http.StatusNotFound)
		return
	}
	challengeModel.ID = idChallenge
	result, err := h.authServices.Challenge(r.Context(), challengeModel)
	if err != nil {
		http.Error(w, "Challenge failed", http.StatusUnauthorized)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(cache))
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		http.Error(w, "Failed to marshal response to JSON", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resultJSON)
}

func (h *AuthHandler) TokenHandler(w http.ResponseWriter, r *http.Request) {
	var challengeModel models.TokenRequest
	err := json.NewDecoder(r.Body).Decode(&challengeModel)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	vars := mux.Vars(r)
	idChallenge := vars["id"]
	h.logger.Infof("Received Token ID: %s", idChallenge)
	cache, err := h.cache.Get(r.Context(), idChallenge)
	if err != nil {
		http.Error(w, "token id not found", http.StatusNotFound)
		return
	}
	challengeModel.ID = idChallenge
	result, err := h.authServices.Token(r.Context(), challengeModel)
	if err != nil {
		http.Error(w, "token failed", http.StatusUnauthorized)

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(cache))
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		http.Error(w, "Failed to marshal response to JSON", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resultJSON)
}
func (h *AuthHandler) WithContext(ctx context.Context, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handler(w, r)
	}
}
func (h *AuthHandler) IntrospectHandler(w http.ResponseWriter, r *http.Request) {
	var token = r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	_, err := h.authServices.Introspect(r.Context(), token)
	if err != nil {
		http.Error(w, "Introspect failed", http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)

}
