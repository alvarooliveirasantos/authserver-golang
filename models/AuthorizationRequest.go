package models

type AuthorizationRequest struct {
	Response_type string `json:"response_type"`
	User_agent    string `json:"user-agent"`
	Client_id     string `json:"client_id"`
	Scope         string `json:"scope"`
	State         string `json:"state"`
}

type IdentityRequest struct {
	Type     string `json:"type"`
	Identity string `json:"identity"`
}
type ChallengeRequest struct {
	ID        string `json:"id"`
	Password  string `json:"password"`
	Client_id string `json:"client_id"`
}
type UserData struct {
	Identity string
	Password string
}

type CodeData struct {
	Code      string
	Client_id string
}
type TokenRequest struct {
	ID        string `json:"id"`
	Code      string `json:"code"`
	Client_id string `json:"client_id"`
}
