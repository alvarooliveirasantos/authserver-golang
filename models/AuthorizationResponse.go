package models

type AuthorizationResponse struct {
	Status       string `json:"status"`
	URI          string `json:"uri"`
	Submitaction string `json:"submitaction"`
	Type         string `json:"type"`
}
type IdentityResponse struct {
	Type         string `json:"type"`
	Submitaction string `json:"submitaction"`
}
type ChallengeResponse struct {
	Code         string `json:"code"`
	Submitaction string `json:"submitaction"`
}
type TokenResponse struct {
	AccessToken        string `json:"access_token"`
	TokenType          string `json:"token_type"`
	ExpiresIn          int    `json:"expires_in"`
	RefreshToken       string `json:"refresh_token"`
	RefreshTokenExpiry int    `json:"refresh_token_expiry"`
}
