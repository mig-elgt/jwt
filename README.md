# Go JWT Library

JWT Library defines and implements an interface to create and validate JWT tokens.

## Features

* Exports an interface to create and valiate tokens. You can use this interface in your code in order to do dependency injection.

* Create tokens with an expires time.

* Support Generic Data for the token's payload.

# Installation

Standard `go get`:

```
$ go get github.com/mig-elgt/jwt

```

## Usage & Example

A quick code example is shown below:

```go
package main

import (
	"fmt"
	"log"

	"github.com/mig-elgt/jwt"
)

func main() {
	// Create a Token with a Primitive Data Type
	t := jwt.New("secret_key")
	userID := 100
	token, err := t.Create(userID)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(token)
	// Output
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoxMDAsImV4cCI6MTY3NTg3NTcyNH0.CJVX6LQjTxQgiW7aUuNYcot6Re9Ba9DgW7XTm5G91lo

	// Validate Token
	// Token
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjoxMDAsImV4cCI6MTY3NTg3NTcyNH0.CJVX6LQjTxQgiW7aUuNYcot6Re9Ba9DgW7XTm5G91lo
	data, err := t.Validate(token)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(data)
	// Output
	// 100

	// Create a Token with a custom Data Structure and Expires Time (in hours)
	t = jwt.NewWithExpiresAt("secret_key", 10)
	type payload struct {
		UserID int64 `json:"user_id"`
	}
	token, err = t.Create(&payload{UserID: 100})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(token)
	// Output
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7InVzZXJfaWQiOjEwMH0sImV4cCI6MTY3MzQ5NDAzNX0.BBDIZvq4xYLEkMl1G8pX_w7XgyF_RTD0OR1UB1eirVI

	// Validate Token
	// Token
	// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJkYXRhIjp7InVzZXJfaWQiOjEwMH0sImV4cCI6MTY3MzQ5NDAzNX0.BBDIZvq4xYLEkMl1G8pX_w7XgyF_RTD0OR1UB1eirVI
	data, err = t.Validate(token)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(data)
	// Output
	// map[user_id: 100]
}
```
