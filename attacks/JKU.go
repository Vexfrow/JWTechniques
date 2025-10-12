package attacks

import (
	"fmt"
	"net/http"
	"strconv"
)

func changeJKUValue(JSONFile string) {
}

func LaunchServer(port int, jsonFile string) {

	fmt.Printf("Server launch on port %d\n", port)

	fs := http.FileServer(http.Dir("./files"))

	http.Handle("/", fs)

	http.ListenAndServe(":"+strconv.Itoa(port), nil)
}

func ExploitJKU(tokenString string) {

	// token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
	// 	return []byte("AllYourBase"), nil
	// })

	// if err != nil {
	// 	fmt.Printf("err = %s \n", err)
	// } else {
	// 	fmt.Printf("Token = %s", token)
	// }

	// test := jwt.ParseWithClaims(token)

	// launchServer(12345)

	// //Convert the JWT string into a JWT object
	// jwtoken := jwt.New(jwt.SigningMethodES256)
}
