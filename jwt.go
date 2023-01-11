package jwt

import (
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

// TokenCreateValidator describes the JWT operations.
type TokenCreateValidator interface {
	Create(payload interface{}) (string, error)
	Validate(string) (interface{}, error)
}

// jwt represents a Token implementation of TokenCreateValidator interface.
type jwt struct {
	// secret describes a secret key to use with the token
	secret    string
	expiresAt time.Duration
}

// New creates new JWT object given a secret value
func New(secret string) TokenCreateValidator {
	return &jwt{
		secret: secret,
		// Default expires time to one month
		expiresAt: time.Hour * 24 * 7 * 4,
	}
}

// NewWithExpiresAt creates new JWT object with an expires time
func NewWithExpiresAt(secret string, expiresAt int) TokenCreateValidator {
	return &jwt{
		secret:    secret,
		expiresAt: time.Hour * time.Duration(expiresAt),
	}
}

// Create creates, signs, and encodes a JWT token using the HMAC signing method
func (t jwt) Create(data interface{}) (string, error) {
	// create a signer for HS256
	token := jwtgo.New(jwtgo.GetSigningMethod("HS256"))
	// set our claims
	token.Claims = &customClaim{
		data,
		jwtgo.StandardClaims{
			ExpiresAt: time.Now().Add(t.expiresAt).Unix(),
		},
	}
	// create a token string
	return token.SignedString([]byte(t.secret))
}

// customClaim represents the user custom payload to store into a token.
type customClaim struct {
	// Data stores the user data
	Data interface{} `json:"data"`
	jwtgo.StandardClaims
}

// Validate validates tokens using a secret key and custom claim.
// it returns an error in case the token is malformed or expired.
func (t jwt) Validate(secret string) (interface{}, error) {
	token, err := jwtgo.ParseWithClaims(secret, &customClaim{}, func(token *jwtgo.Token) (interface{}, error) {
		return []byte(t.secret), nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not parse token with custom claims")
	}
	claims, _ := token.Claims.(*customClaim)
	return claims.Data, nil
}
