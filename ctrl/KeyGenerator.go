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

// Generate a privateKey to sign the token, and create a JWK file to verify the signature
func GenerateJWK(algorithm string) (any, string, error) {

	var privateKey any = nil
	var err error = nil
	var publicKey any = nil

	//Generate the private key according to the algorithm used
	algLower := strings.ToLower(algorithm)
	if strings.Contains(algLower, "rs") {
		privateKey, publicKey, err = generateRSAKeys()
	} else if strings.Contains(algLower, "hs") {
		privateKey, err = generateHMACKey()
		publicKey = privateKey
	} else if strings.Contains(algLower, "es") {
		privateKey, err = generateECDSAKey()
		publicKey = privateKey
	} else if strings.Contains(algLower, "ps") {
		privateKey, err = generateRSAPSSKey()
		publicKey = privateKey
	} else if strings.Contains(algLower, "ed") {
		privateKey, err = generateEdDSAKey()
		publicKey = privateKey
	} else {
		err = fmt.Errorf("Algorithm \"%s\" is unknown\n", algorithm)
	}

	if err != nil {
		return nil, "", err
	}

	pathToFile := prefixFile + algorithm + extension
	err = generateFileFromKey(publicKey, algorithm, Directory+pathToFile)

	return privateKey, pathToFile, err
}

func generateRSAKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	// Generate an RSA private key using rand
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to generate RSA key: %v", err)
	}

	// Generate an RSA public key from the private key
	publicKey := rsa.PublicKey{N: (*privateKey).N, E: int((*privateKey).E)}

	return privateKey, &publicKey, nil
}

func generateHMACKey() (*jwk.Key, error) {
	//TODO

	return nil, nil
}

func generateECDSAKey() (*jwk.Key, error) {
	//TODO

	return nil, nil
}

func generateRSAPSSKey() (*jwk.Key, error) {
	//TODO

	return nil, nil
}

func generateEdDSAKey() (*jwk.Key, error) {
	//TODO

	return nil, nil
}

func generateFileFromKey(key any, alg, pathToFile string) error {
	jwkKey, err := jwk.FromRaw(key)
	if err != nil {
		return fmt.Errorf("Failed to create JWK: %v", err)
	}

	// Set metadata
	jwkKey.Set(jwk.AlgorithmKey, alg)
	jwkKey.Set(jwk.KeyUsageKey, "sig")

	jsonbuf, err := json.MarshalIndent(jwkKey, "", "  ")
	if err != nil {
		return fmt.Errorf("Failed to generate json: %v", err)
	}

	//Write JSON into a new file
	err = os.WriteFile(pathToFile, jsonbuf, 0644)

	return err

}
