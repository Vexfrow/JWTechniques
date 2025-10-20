package ctrl

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func SignJWT(token *jwt.Token, secret any) string {
	JWTString, err := token.SignedString(secret)

	if err != nil {
		fmt.Printf("Failed to sign new token: %v\n", err)
	}

	return JWTString
}

func StringToToken(jwtStr string) *jwt.Token {

	token, _, err := new(jwt.Parser).ParseUnverified(jwtStr, jwt.MapClaims{})

	if err != nil {
		fmt.Printf("Failed to parse token: %v\n", err)
	}

	return token
}

func ChangeValue(token *jwt.Token, header string, value string, isHeader bool) (*jwt.Token, error) {

	newJWTClaims := token.Claims

	//Change the value
	if isHeader {
		if _, ok := token.Header[header]; ok {
			token.Header[header] = value
		} else {
			return nil, fmt.Errorf("Token has no header \"%s\"", header)
		}

	} else {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {

			if _, ok := claims[header]; ok {
				claims[header] = value
				newJWTClaims = claims
			} else {
				return nil, fmt.Errorf("Token has no header \"%s\" in payload fields", header)
			}
		}
	}

	//Get the algo used to sign the token
	algStr, ok := token.Header["alg"]
	if !ok {
		return nil, fmt.Errorf("token has no header \"alg\"")
	}

	signMethod := jwt.GetSigningMethod(algStr.(string))
	if signMethod == nil {
		return nil, fmt.Errorf("value \"%s\" does not correspond with any algorithm usually used", algStr.(string))
	}

	//Create a new token with the same values + the value that has been modified
	newJWT := jwt.NewWithClaims(signMethod, newJWTClaims)

	return newJWT, nil
}

func PrintToken(token *jwt.Token) {

	// Extract headers
	fmt.Println("Headers:")
	for key, value := range token.Header {
		fmt.Printf("%s: %v\n", key, value)
	}

	// Extract payloads
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		fmt.Println("\nClaims:")
		for key, value := range claims {
			fmt.Printf("%s: %v\n", key, value)
		}
	} else {
		fmt.Print("Failed to parse claims as MapClaims")
	}

}
