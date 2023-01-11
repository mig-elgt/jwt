package jwt

import (
	"reflect"
	"testing"
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
)

// func TestNew(t *testing.T) {
// 	for _, tc := range []struct {
// 		name  string
// 		input int64
// 		role  string
// 	}{
// 		{
// 			name:  "should has 3 components: header, payload, signature",
// 			input: 1,
// 			role:  "admin",
// 		},
// 	} {
// 		t.Run(fmt.Sprintf("[case] %s", tc.name), func(t *testing.T) {
// 			token, _ := New("secret").Create(tc.input, tc.role)
// 			got := len(strings.Split(string(token), "."))
// 			if got != 3 {
// 				t.Errorf("got %v; want 3", got)
// 			}
// 		})
// 	}
// }

// func TestJWT_Create(t *testing.T) {
// 	type payload struct {
// 		id   int
// 		role string
// 	}
// 	for _, tc := range []struct {
// 		name string
// 		data *payload
// 	}{
// 		{
// 			name: "should has 3 components: header, payload, signature",
// 			data: &payload{id: 1, role: "admin"},
// 		},
// 	} {
// 		t.Run(fmt.Sprintf("[case] %s", tc.name), func(t *testing.T) {
// 			token, _ := New("secret").Create(tc.data)
// 			got := len(strings.Split(string(token), "."))
// 			if got != 3 {
// 				t.Errorf("got %v; want 3", got)
// 			}
// 		})
// 	}
// }

func TestJWT_Validate(t *testing.T) {
	type payload struct {
		ID   int    `json:"id"`
		Role string `json:"role"`
	}
	type args struct {
		data   *payload
		create func(data interface{}) (string, error)
	}
	cases := []struct {
		name        string
		args        args
		wantPayload map[string]interface{}
		wantErr     bool
	}{
		{
			name: "signature incorrect",
			args: args{
				data: &payload{ID: 1, Role: "admin"},
				create: func(data interface{}) (string, error) {
					token := jwtgo.New(jwtgo.GetSigningMethod("HS256"))
					token.Claims = &customClaimsGenericData{data, jwtgo.StandardClaims{}}
					return token.SignedString([]byte("fake_secret"))
				},
			},
			wantErr: true,
		},
		{
			name: "base case",
			args: args{
				data: &payload{ID: 10, Role: "admin"},
				create: func(data interface{}) (string, error) {
					token := jwtgo.New(jwtgo.GetSigningMethod("HS256"))
					token.Claims = &customClaimsGenericData{data, jwtgo.StandardClaims{}}
					return token.SignedString([]byte("secret"))
				},
			},
			wantErr: false,
			wantPayload: map[string]interface{}{
				"id":   float64(10),
				"role": "admin",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			toker := jwt{secret: "secret", expiresAt: time.Second * 10}
			token, _ := tc.args.create(tc.args.data)
			pl, err := toker.Validate(token)
			if (err != nil) != tc.wantErr {
				t.Fatalf("jwt.Validate() got error: %v; want %v", err, tc.wantErr)
			}
			if !tc.wantErr && !reflect.DeepEqual(pl, tc.wantPayload) {
				t.Fatalf("jwt.Validate() got payload: %v; want %v", pl, tc.wantPayload)
			}
		})
	}
}
