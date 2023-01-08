package jwt

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
)

func TestNew(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input int64
		role  string
	}{
		{
			name:  "should has 3 components: header, payload, signature",
			input: 1,
			role:  "admin",
		},
	} {
		t.Run(fmt.Sprintf("[case] %s", tc.name), func(t *testing.T) {
			token, _ := New("secret").Create(tc.input, tc.role)
			got := len(strings.Split(string(token), "."))
			if got != 3 {
				t.Errorf("got %v; want 3", got)
			}
		})
	}
}

func TestJWT_Validate(t *testing.T) {
	type args struct {
		id     int64
		role   string
		create func(id int64, role string) string
	}
	cases := []struct {
		name        string
		args        args
		wantPayload *PayloadContent
		wantErr     bool
	}{
		{
			name: "signature incorrect",
			args: args{
				id:   1,
				role: "admin",
				create: func(id int64, role string) string {
					token := jwtgo.New(jwtgo.GetSigningMethod("HS256"))
					token.Claims = &customClaims{id, role, jwtgo.StandardClaims{}}
					t, _ := token.SignedString([]byte("fake_secret"))
					return t
				},
			},
			wantErr: true,
		},
		{
			name: "base case",
			args: args{
				id:   10,
				role: "admin",
				create: func(id int64, role string) string {
					token := jwtgo.New(jwtgo.GetSigningMethod("HS256"))
					token.Claims = &customClaims{id, role, jwtgo.StandardClaims{}}
					t, _ := token.SignedString([]byte("secret"))
					return t
				},
			},
			wantErr:     false,
			wantPayload: &PayloadContent{10, "admin"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jsonWebToken := jwt{secret: "secret", expiresAt: time.Second * 10}
			if pl, err := jsonWebToken.Validate(tc.args.create(tc.args.id, tc.args.role)); (err != nil) != tc.wantErr {
				t.Errorf("jwt.Validate() error got: %v; want %v", err, tc.wantErr)
			} else if !tc.wantErr && !reflect.DeepEqual(pl, tc.wantPayload) {
				t.Errorf("jwt.Validate() Payload got: %v; want %v", pl, tc.wantPayload)
			}
		})
	}
}
