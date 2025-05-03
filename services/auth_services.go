package services

import (
	"auth-server/config"
	"auth-server/models"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

var users = map[string]string{
	"41444055836": "123456",
	"user2":       "password2",
}

type AuthServiceInterface interface {
	Authenticate(ctx context.Context, creds Credentials) (string, error)
	Authorization(ctx context.Context, authorizationRequest models.AuthorizationRequest) (models.AuthorizationResponse, error)
	Identity(ctx context.Context, identityRequest models.IdentityRequest) (models.IdentityResponse, error)
	Challenge(ctx context.Context, challengeRequest models.ChallengeRequest) (models.ChallengeResponse, error)
	Token(ctx context.Context, tokenRequest models.TokenRequest) (models.TokenResponse, error)
	Introspect(ctx context.Context, token string) (bool, error)
}
type AuthServices struct {
	ctx    context.Context
	logger *logrus.Logger
	cache  config.Cache
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func NewAuthService(ctx context.Context) *AuthServices {
	logger := ctx.Value("logger").(*logrus.Logger)
	cache := ctx.Value("cache").(config.Cache)
	return &AuthServices{ctx: ctx, cache: cache, logger: logger}
}

func (s *AuthServices) Authenticate(ctx context.Context, creds Credentials) (string, error) {
	if password, ok := users[creds.Username]; ok {
		if password == creds.Password {
			s.logger.Info("User ", creds.Username, " authenticated")
			return s.generateJWT(creds.Username, ctx)

		}
	}
	return "", errors.New("invalid credentials")
}
func (s *AuthServices) Authorization(ctx context.Context, authorizationModel models.AuthorizationRequest) (models.AuthorizationResponse, error) {
	s.logger.Info("Authorize request", authorizationModel)
	authURL := url.URL{
		Scheme: "https",
		Host:   "authorization-server.com",
		Path:   "/oauth/authorize",
		RawQuery: url.Values{
			"scope": {authorizationModel.Scope},
		}.Encode(),
	}
	response := models.AuthorizationResponse{
		Status: "IDENTITY_REQUIRED", URI: authURL.String(), Submitaction: uuid.New().String(), Type: "CPF",
	}
	responseJSON, err := json.Marshal(response)
	if err != nil {
		s.logger.Error("Failed to marshal response to JSON", err)
		return models.AuthorizationResponse{}, err
	}
	s.cache.Set(ctx, response.Submitaction, responseJSON, time.Minute*1)

	return response, nil

}
func (s *AuthServices) Identity(ctx context.Context, challengeModel models.IdentityRequest) (models.IdentityResponse, error) {
	s.logger.Info("identity request", challengeModel)
	var identityKey string = uuid.New().String()
	responseJSON, err := json.Marshal(challengeModel)
	if err != nil {
		s.logger.Error("Failed to marshal response to JSON", err)
		return models.IdentityResponse{}, err
	}

	s.cache.Set(ctx, identityKey, responseJSON, time.Minute*1)
	return models.IdentityResponse{
		Type:         "password",
		Submitaction: identityKey,
	}, nil

}
func (s *AuthServices) Challenge(ctx context.Context, challengeModel models.ChallengeRequest) (models.ChallengeResponse, error) {
	s.logger.Info("Challenge request", challengeModel)
	identityChallenge, err := s.cache.Get(ctx, challengeModel.ID)
	if err != nil {
		return models.ChallengeResponse{}, err
	}
	var identity models.IdentityRequest
	err = json.Unmarshal([]byte(identityChallenge), &identity)
	if err != nil {
		return models.ChallengeResponse{}, err
	}
	if valid, _ := s.ValidateChallange(identity.Identity, challengeModel.Password); valid {
		var submitaction = uuid.New().String()
		var code = uuid.New().String()
		CodeData := models.CodeData{Code: code, Client_id: challengeModel.Client_id}
		responseJSON, err := json.Marshal(CodeData)
		if err != nil {
			s.logger.Error("Failed to marshal response to JSON", err)
			return models.ChallengeResponse{}, err
		}
		s.cache.Set(ctx, submitaction, responseJSON, time.Minute*1)

		return models.ChallengeResponse{
			Code:         code,
			Submitaction: submitaction,
		}, nil
	}

	s.cache.Set(ctx, challengeModel.ID, "invalid", time.Minute*1)
	return models.ChallengeResponse{}, errors.New("invalid credentials")
}
func (s *AuthServices) ValidateChallange(identity string, password string) (bool, error) {
	if storedPassword, ok := users[identity]; ok {
		if password == storedPassword {
			s.logger.Info("User ", identity, " authenticated")
			return true, nil

		}
	}
	return false, nil
}
func (s *AuthServices) Token(ctx context.Context, tokenModel models.TokenRequest) (models.TokenResponse, error) {
	s.logger.Info("Token request", tokenModel)
	codeChallenge, err := s.cache.Get(ctx, tokenModel.ID)
	if err != nil {
		return models.TokenResponse{}, err
	}
	var codeData models.CodeData
	err = json.Unmarshal([]byte(codeChallenge), &codeData)
	if err != nil {
		return models.TokenResponse{}, err
	}
	if codeData.Client_id != tokenModel.Client_id {
		return models.TokenResponse{}, errors.New("invalid client")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": codeData.Code,
		"exp":      time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		return models.TokenResponse{}, err
	}
	err = s.cache.Set(ctx, codeData.Code, tokenString, time.Hour*1)
	if err != nil {
		log.Println("Error setting token in Redis", err)
		return models.TokenResponse{}, err
	}
	return models.TokenResponse{
		AccessToken:        tokenString,
		TokenType:          "Bearer",
		ExpiresIn:          3600,
		RefreshToken:       "refreshToken",
		RefreshTokenExpiry: 3600,
	}, nil
}
func (s *AuthServices) generateJWT(username string, ctx context.Context) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		return "", err
	}
	err = s.cache.Set(ctx, username, tokenString, time.Hour*1)
	if err != nil {
		log.Println("Error setting token in Redis", err)
		return "ERRO", err
	}
	return tokenString, nil
}
func (s *AuthServices) Introspect(ctx context.Context, token string) (bool, error) {
	// Check if the token is valid and not expired
	claims := &jwt.MapClaims{}
	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})
	if err != nil {
		return false, err
	}
	if !tkn.Valid {
		return false, errors.New("invalid token")
	}
	s.logger.Info("Token introspection successful")
	return true, nil
}
