package main

import "github.com/golang-jwt/jwt/v5"

type userKeyAuthRequest struct {
	AccountId    string       `json:"accountIdentifier"`
	SshKeyObject sshKeyObject `json:"sshKeyObject"`
	SshKey       string       `json:"sshKey"`
}

type sshKeyObject struct {
	Key       string `json:"key"`
	Algorithm string `json:"algorithm"`
}

type PrincipalType string

const PrincipalTypeService PrincipalType = "SERVICE"

type UserKeyAuthResponse struct {
	Data   Data   `json:"data"`
	Status string `json:"status"`
}

type Data struct {
	UUID string `json:"uuid"`
}

type UserClusterResponse struct {
	ClusterName string `json:"clusterName"`
}

// JWTClaims represents the claims structure for JWT tokens
// using the modern jwt/v5 RegisteredClaims
type JWTClaims struct {
	jwt.RegisteredClaims

	// Common claims
	Type PrincipalType `json:"type,omitempty"`
	Name string        `json:"name,omitempty"`

	// Used only by user / service account
	Email     string `json:"email,omitempty"`
	UserName  string `json:"username,omitempty"`
	AccountID string `json:"accountId,omitempty"`
}
