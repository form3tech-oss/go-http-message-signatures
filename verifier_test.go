package httpsignatures

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewRSAVerifier_UnknownAlgo(t *testing.T) {
	_, err := NewRSAVerifier(&rsa.PublicKey{}, crypto.SHA1)
	assert.Error(t, err)
}

func Test_NewRSAVerifier_NilPublicKey(t *testing.T) {
	_, err := NewRSAVerifier(nil, crypto.SHA256)
	assert.Error(t, err)
}

func Test_NewRSAVerifier_NotRSAPublicKey(t *testing.T) {
	_, err := NewRSAVerifier(&ecdsa.PublicKey{}, crypto.SHA256)
	assert.Error(t, err)
}

func Test_NewRSAVerifier(t *testing.T) {
	_, err := NewRSAVerifier(rsaPublicKey(), crypto.SHA256)
	assert.NoError(t, err)
}

type verifyTestCase struct {
	title         string
	b64Signature  string
	content       []byte
	algo          crypto.Hash
	errorExpected bool
}

func (tc *verifyTestCase) test(t *testing.T) {
	verifier, err := NewRSAVerifier(rsaPublicKey(), tc.algo)
	require.NoError(t, err)

	signature, err := base64.StdEncoding.DecodeString(tc.b64Signature)
	require.NoError(t, err)

	err = verifier.Verify(signature, tc.content)
	if tc.errorExpected {
		assert.Error(t, err)
	} else {
		assert.NoError(t, err)
	}
}

func Test_RSAVerifier_Verify(t *testing.T) {
	testCases := []verifyTestCase{
		{
			title: "sha256 valid signature",
			// signature generated using (echo -n -e "test" | openssl dgst -sha256 -sign test-certificates/rsa.pem | openssl base64)
			b64Signature:  "SZeXeLqG2DNAo2QGVGnfKi684YGXCkgWGtMJQCJ49At6H2LqRLFHsHeTz619rFtYw509dh6ORrxUggQPIT7+UIhFLd3jQWNBIj+skVPctGzuF3vZgYI1bTsjB8fiZumoZF59kDdaPBQ+68s6FvjvegC6w2wbnYUGrhUb6toGamgf7yLsauKT2R8QoVji+YDd31VIbb7ulYAHl452lD8u23uNK4oP/EXtGaXfrXMf/RLzRjgi+JsiZLL6T2ah01tuSorZnFUlcNM8+cYC9Erim9wYO3zOhPiiZhiklltKnuP7OZ/OX6sl/woMM0tRCf2S+ar6N3ru56d574LtNe9/Rg==",
			content:       []byte("test"),
			algo:          crypto.SHA256,
			errorExpected: false,
		},
		{
			title: "sha256 invalid signature",
			// signature generated using (echo -n -e "not a valid signature" | base64)
			b64Signature:  "bm90IGEgdmFsaWQgc2lnbmF0dXJl",
			content:       []byte("test"),
			algo:          crypto.SHA256,
			errorExpected: true,
		},
		{
			title: "sha512 valid signature",
			// signature generated using (echo -n -e "test" | openssl dgst -sha512 -sign test-certificates/rsa.pem | openssl base64)
			b64Signature:  "LnDwf9ImqyKY8ZbQFJMh3NwfbvPBl737FPr7kn7TngH7eggiLq7cHagqxXXuUaPCfdwF7oAXOdLriRFkeIgtyTgx11zq6l7uCq/M9jDpaKGUqNBau9Trt3viZ2swpVKG/UZMIYCxPFWLC+yaocsAvdZiHcLXWBlqPB6sFYNIWGlfsGvpUVHx82qsEg9LffhDFVhJ5FAslkKuG6j1aba0gMIBvD9plXN8CR0YQJRR6RmKiFTFUREjhs2ULdi6O/dnyxy95XyWv1ROixatpMXX4mrBCr/ZjnJuQy05OU8S2qYZDNAe0Q9RsPpFQc7BIsGxtvTDlYVuO83HrvC0qz4s7g==",
			content:       []byte("test"),
			algo:          crypto.SHA512,
			errorExpected: false,
		},
		{
			title: "sha512 invalid signature",
			// signature generated using (echo -n -e "not a valid signature" | base64)
			b64Signature:  "bm90IGEgdmFsaWQgc2lnbmF0dXJl",
			content:       []byte("test"),
			algo:          crypto.SHA512,
			errorExpected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, tc.test)
	}
}

func Fuzz_RSAVerifier_VerifySHA256(f *testing.F) {
	rv, _ := NewRSAVerifier(rsaPublicKey(), crypto.SHA256)

	f.Add([]byte("signature"), []byte("content"))
	f.Fuzz(func(t *testing.T, s, c []byte) {
		defer func() {
			if recover() != nil {
				t.Errorf("Panic caught during fuzzing:\nInput: %v\nOutput: %v", s, c)
			}
		}()

		err := rv.Verify(s, c)
		if err != nil || err == nil {
			return
		}
	})
}

func Fuzz_RSAVerifier_VerifySHA512(f *testing.F) {
	rv, _ := NewRSAVerifier(rsaPublicKey(), crypto.SHA512)

	f.Add([]byte("signature"), []byte("content"))
	f.Fuzz(func(t *testing.T, s, c []byte) {
		defer func() {
			if recover() != nil {
				t.Errorf("Panic caught during fuzzing:\nInput: %v\nOutput: %v", s, c)
			}
		}()

		err := rv.Verify(s, c)
		if err != nil || err == nil {
			return
		}
	})
}

func Fuzz_RSASignAndVerify(f *testing.F) {
	rs, _ := NewRSASigner(rsaPrivateKey(), crypto.SHA256)
	rv, _ := NewRSAVerifier(rsaPublicKey(), crypto.SHA256)

	f.Add([]byte("content"))
	f.Fuzz(func(t *testing.T, b []byte) {
		signature, err := rs.Sign(rand.Reader, b)
		if err != nil {
			t.Errorf("Failed to sign:\nInput: %v\nOutput: %v\nError:%v", b, signature, err)
		}
		err = rv.Verify(signature, b)
		if err != nil {
			t.Errorf("Failed to verify:\nInput: %v\nOutput: %v\nError:%v", b, signature, err)
		}
	})
}

func rsaPublicKey() *rsa.PublicKey {
	keyBytes, _ := os.ReadFile("./test-certificates/rsa.pub")
	decoded, _ := pem.Decode(keyBytes)
	pk, _ := x509.ParsePKIXPublicKey(decoded.Bytes)
	return pk.(*rsa.PublicKey)
}
