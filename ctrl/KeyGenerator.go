package ctrl

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

const (
	Directory  string = "/files/"
	prefixFile string = "jwk-"
)

func GenerateJWK(algorithm string) (any, string, error) {

	var privateKey any = nil
	var err error = nil
	var publicKey any = nil

	//Generate the private key
	algLower := strings.ToLower(algorithm)
	if strings.Contains(algLower, "rs") {
		privateKey, publicKey, err = generateRSAKeys()
	} else if strings.Contains(algLower, "hs") {
		privateKey, err = generateHMACKey()
	} else if strings.Contains(algLower, "es") {
		privateKey, err = generateECDSAKey()
	} else if strings.Contains(algLower, "ps") {
		privateKey, err = generateRSAPSSKey()
	} else if strings.Contains(algLower, "ed") {
		privateKey, err = generateEdDSAKey()
	} else {
		err = fmt.Errorf("Error : Algorithm \"%s\" is unknown\n", algorithm)
	}

	if err != nil {
		return nil, "", err
	}

	// Set metadata
	// (*privateKey).Set(jwk.AlgorithmKey, algorithm)
	// (*privateKey).Set(jwk.KeyUsageKey, "sig")

	// // Marshal to JSON
	// jsonbuf, err := json.MarshalIndent(*privateKey, "", "  ")
	// if err != nil {
	// 	return nil, "", err
	// }

	pathToFile := Directory + prefixFile + algorithm

	//Write JSON into a new file
	//	err = os.WriteFile(pathToFile, jsonbuf, os.FileMode(os.O_CREATE))
	if err != nil {
		return nil, "", err
	}

	if strings.Contains(algLower, "rs") {
		//	jwt.public
	}

	return privateKey, pathToFile, nil
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
