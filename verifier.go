package httpsignatures

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"strings"
)

// NewVerifier describes a function for creating a new instance of Verifier.
type NewVerifier func(publicKey crypto.PublicKey, cryptoHash crypto.Hash) (Verifier, error)

// newVerifier fetches the correct Verifier from the given signingAlgo. If an algo is provided,
// it will be verified against the hashing algorithm in signingAlgo.
func newVerifier(publicKey crypto.PublicKey, algo crypto.Hash, signingAlgo string) (Verifier, error) {
	var signingHash string
	var verifier NewVerifier
	if strings.HasPrefix(signingAlgo, rsaName) {
		signingHash = strings.TrimPrefix(signingAlgo, rsaName+"-")
		verifier = NewRSAVerifier
	}

	if algo != 0 {
		cryptoHash, err := fetchCryptoHash(algo)
		if err != nil {
			return nil, NewInitialisationError("required hashing algorithm is unknown or unsupported", err)
		}

		if cryptoHash.Name != signingHash {
			return nil, NewValidationError(
				fmt.Sprintf(
					"hashing algorithm provided in signature (%s) did not match expected algorithm (%s)",
					signingHash,
					cryptoHash.Name,
				),
			)
		}
	}

	if verifier == nil {
		return nil, NewValidationError(fmt.Sprintf("no verifier could be found for %s", signingAlgo))
	}
	return verifier(publicKey, getAlgoByName(signingHash))
}

// Verifier is the interface that wraps the basic Verify method.
//
// Verify verifies if the signature is valid for the provided content. It returns an error if the
// signature is invalid or any error encountered that caused the verify to stop early. Verify must
// not modify the slice data, even temporarily.
//
// Implementations must not retain content.
type Verifier interface {
	// Verify the given signature against content.
	Verify(signature, content []byte) error
}

// RSAVerifier implements Verifier interface and uses RSA private key to sign content.
type RSAVerifier struct {
	// publicKey is the key used to sign the data.
	publicKey *rsa.PublicKey
	// algo is the hashing algorithm to use when verifying.
	algo *HashingAlgorithm
}

// compile time check that RSAVerifier implements Verifier.
var _ Verifier = &RSAVerifier{}

// NewRSAVerifier verifies that the given algorithm is supported and returns a new instance
// of RSAVerifier.
func NewRSAVerifier(publicKey crypto.PublicKey, algo crypto.Hash) (Verifier, error) {
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, NewInitialisationError("public key provided is not an RSA public key", nil)
	}

	hashingAlgo, err := fetchCryptoHash(algo)
	if err != nil {
		return nil, NewInitialisationError("hashing algorithm is unknown or unsupported", err)
	}

	return &RSAVerifier{
		publicKey: rsaPublicKey,
		algo:      hashingAlgo,
	}, nil
}

// Sign hashes the content and then signs it.
func (r *RSAVerifier) Verify(signature, content []byte) error {
	hasher := r.algo.FetchHasher()
	hasher.Write(content)
	return rsa.VerifyPKCS1v15(r.publicKey, r.algo.Hash, hasher.Sum(nil), signature)
}

// getAlgoByName finds the crypto hash for the given name.
func getAlgoByName(name string) crypto.Hash {
	switch name {
	case sha256Name:
		return crypto.SHA256
	case sha512Name:
		return crypto.SHA512
	}

	return 0
}
