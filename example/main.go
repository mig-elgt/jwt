package main

import (
	"fmt"
	"log"

	"github.com/mig-elgt/jwt"
)

func main() {
	toker := jwt.New("secret_key")
	type payload struct {
		ID int64
	}
	token, err := toker.Create(&payload{ID: 100})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(token)

	data, err := toker.Validate(token)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(data)
}
