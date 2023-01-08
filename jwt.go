package jwt

import (
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

// JWTCreator represents the JWT behavior.
type TokenCreateValidator interface {
	Create(id int64, role string) (string, error)
	Validate(string) (*PayloadContent, error)
}

// jwt represents a Token implementation of JWTCreator interface.
type jwt struct {
	secret    string
	expiresAt time.Duration
}

// New creates new JWT object and set its secret key.
func New(secret string) *jwt {
	return &jwt{
		secret: secret,
		// Default expires time to 1 month
		expiresAt: time.Hour * 24 * 7 * 4,
	}
}

func NewWithExpiresAt(secret string, expiresAt int) *jwt {
	return &jwt{
		secret:    secret,
		expiresAt: time.Hour * time.Duration(expiresAt),
	}
}

// customClaims represents the payload information about the user
// to save into JWT token.
type customClaims struct {
	ID   int64  `json:"id"`
	Role string `json:"role"`

	jwtgo.StandardClaims
}

// Create creates, signs, and encodes a JWT token using the HMAC signing method
func (t jwt) Create(id int64, role string) (string, error) {
	// create a signer for HS256
	token := jwtgo.New(jwtgo.GetSigningMethod("HS256"))
	// set our claims
	token.Claims = &customClaims{
		id,
		role,
		jwtgo.StandardClaims{
			ExpiresAt: time.Now().Add(t.expiresAt).Unix(),
		},
	}
	// create token string
	return token.SignedString([]byte(t.secret))
}

type PayloadContent struct {
	ID   int64
	Role string
}

// Validate validates tokens using a secret key and custom claim.
// it returns an error in case the token is malformed or expired.
func (t jwt) Validate(tokenString string) (*PayloadContent, error) {
	token, err := jwtgo.ParseWithClaims(tokenString, &customClaims{}, func(token *jwtgo.Token) (interface{}, error) {
		return []byte(t.secret), nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed parse with claims")
	}
	claims, _ := token.Claims.(*customClaims)
	return &PayloadContent{claims.ID, claims.Role}, nil
}
