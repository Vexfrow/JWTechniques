package ctrl

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

const (
	Directory  string = "files/"
	prefixFile string = "jwk-"
	extension  string = ".json"
)

// Create a JWK, from a key, to verify the signature
func GenerateJWK(key any, algorithm string) ([]byte, error) {

	var jsonBuf []byte

	//Create jwk from raw key
	jwkKey, err := jwk.FromRaw(key)
	if err != nil {
		return jsonBuf, fmt.Errorf("Failed to create JWK: %v", err)
	}

	// Set metadata
	jwkKey.Set(jwk.AlgorithmKey, algorithm)
	jwkKey.Set(jwk.KeyUsageKey, "sig")

	//Generate json from jwk
	jsonBuf, err = json.MarshalIndent(jwkKey, "", "  ")
	if err != nil {
		err = fmt.Errorf("Failed to generate json: %v", err)
	}

	return jsonBuf, err
}

func WriteIntoFile(nameFile string, content []byte) (string, error) {
	//Write the json into a file
	pathToFile := prefixFile + nameFile + extension
	err := os.WriteFile(Directory+pathToFile, content, 0644)

	return pathToFile, err

}

// Generate public/private keys pairs (if the algorithm used is symmetric, public key = private key)
func GenerateKeys(algorithm string) (any, any, error) {

	var privateKey any = nil
	var err error = nil
	var publicKey any = nil

	//Generate the private key according to the algorithm used
	alg := strings.ToLower(algorithm)[0:2]
	fmt.Printf("algo = %s / %s\n", algorithm, alg)
	switch alg {
	case "rs":
		privateKey, publicKey, err = GenerateRSAKeys()

	case "hs":
		privateKey, err = GenerateHMACKey()
		publicKey = privateKey

	case "es":
		privateKey, err = GenerateECDSAKey()
		publicKey = privateKey

	case "ps":
		privateKey, err = GenerateRSAPSSKey()
		publicKey = privateKey

	case "ed":
		privateKey, err = GenerateEdDSAKey()
		publicKey = privateKey

	default:
		err = fmt.Errorf("Algorithm \"%s\" is unknown\n", algorithm)
	}

	return publicKey, privateKey, err
}

func GenerateRSAKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	// Generate an RSA private key using rand
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to generate RSA key: %v", err)
	}

	// Generate an RSA public key from the private key
	publicKey := rsa.PublicKey{N: (*privateKey).N, E: int((*privateKey).E)}

	return privateKey, &publicKey, nil
}

func GenerateHMACKey() (any, error) {
	//TODO

	return nil, nil
}

func GenerateECDSAKey() (any, error) {
	//TODO

	return nil, nil
}

func GenerateRSAPSSKey() (any, error) {
	//TODO

	return nil, nil
}

func GenerateEdDSAKey() (any, error) {
	//TODO

	return nil, nil
}
