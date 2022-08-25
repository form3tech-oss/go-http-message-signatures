package httpsignatures

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"
)

const (
	sha256Name = "sha256"
	sha512Name = "sha512"
	rsaName    = "rsa"
)

// HashingAlgorithm provides a way to get the hashing function and name.
type HashingAlgorithm struct {
	Hash        crypto.Hash
	Name        string
	FetchHasher func() hash.Hash
}

// fetchCryptoHash returns supported hashes.
func fetchCryptoHash(algo crypto.Hash) (*HashingAlgorithm, error) {
	//nolint:exhaustive // we only want to include the hashes we support
	switch algo {
	case crypto.SHA256:
		return &HashingAlgorithm{algo, sha256Name, sha256.New}, nil
	case crypto.SHA512:
		return &HashingAlgorithm{algo, sha512Name, sha512.New}, nil
	default:
		return nil, NewInitialisationError(fmt.Sprintf("crypto hash is unknown or unsupported: %s", algo), nil)
	}
}

// Signer is the interface that wraps the basic Sign method.
//
// Sign signs given content using rand as a good source of entropy for blinding the signing
// operation. It returns the generated signature and any error encountered that caused sign
// to stop early. Sign must return a non-nil error if it cannot properly generate the requested
// signature. Sign must not modify the slice content, even temporarily.
type Signer interface {
	// Sign the given content.
	Sign(rand io.Reader, content []byte) ([]byte, error)
	// String returns the name of the algorithm used to sign the content.
	String() string
}

// RSASigner uses RSA private key to sign content.
type RSASigner struct {
	// privateKey is the key used to sign the data.
	privateKey *rsa.PrivateKey
	// algo is the hashing algorithm to use when signing.
	algo *HashingAlgorithm
}

// compile time check that RSASigner implements Signer.
var _ Signer = &RSASigner{}

// NewRSASigner verifies that the given algorithm is supported and returns a new instance
// of RSASigner.
func NewRSASigner(privateKey *rsa.PrivateKey, algo crypto.Hash) (Signer, error) {
	cryptoHash, err := fetchCryptoHash(algo)
	if err != nil {
		return nil, NewInitialisationError("could not retrieve crypto hash", err)
	}

	if privateKey == nil {
		return nil, NewInitialisationError("private key must not be nil", nil)
	}

	return &RSASigner{
		privateKey: privateKey,
		algo:       cryptoHash,
	}, nil
}

// Sign hashes the content and then signs it.
func (r *RSASigner) Sign(rand io.Reader, content []byte) ([]byte, error) {
	hasher := r.algo.FetchHasher()
	if _, err := hasher.Write(content); err != nil {
		return nil, NewHashingError("failed to write content to hasher", err)
	}

	hashedContent := hasher.Sum(nil)

	return rsa.SignPKCS1v15(rand, r.privateKey, r.algo.Hash, hashedContent)
}

// String returns the rsa name and hashing algorithm separated by a dash.
func (r *RSASigner) String() string {
	return fmt.Sprintf("%s-%s", rsaName, r.algo.Name)
}
