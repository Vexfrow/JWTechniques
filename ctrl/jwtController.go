package ctrl

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)


func StringToToken(jwtStr string) *jwt.Token {

	token, _, err := new(jwt.Parser).ParseUnverified(jwtStr, jwt.MapClaims{})

	if err != nil {
		fmt.Printf("Failed to parse token: %v\n", err)
	}

	return token
}


//Change the value of the given header
func ChangeValue(token *jwt.Token, header string, value string, isHeader bool) (*jwt.Token, error) {

	//Change the value
	if isHeader {
		if _, ok := token.Header[header]; ok {
			token.Header[header] = value

			//If alg is modified, also modified the signing method
			if header == "alg"{
				signMethod := jwt.GetSigningMethod(value)
				token.Method = signMethod
			}
		} else {
			return nil, fmt.Errorf("Token has no header \"%s\"", header)
		}

	} else {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {

			if _, ok := claims[header]; ok {
				claims[header] = value
			} else {
				return nil, fmt.Errorf("Token has no header \"%s\" in payload fields", header)
			}
		}
	}

	return token, nil
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

//Take a token and return a copy
func CloneToken(token *jwt.Token) *jwt.Token{
	tokenCpy := *token

	tokenCpy.Header = make(map[string]interface{}, len(token.Header))
	for k, v := range token.Header {
			tokenCpy.Header[k] = v
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
			newClaims := make(jwt.MapClaims, len(claims))
			for k, v := range claims {
				newClaims[k] = v
			}
			tokenCpy.Claims = newClaims
	}

	return &tokenCpy
}
