package httpsignatures

import (
	"crypto"
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

func Test_NewRSASigner_UnknownAlgo(t *testing.T) {
	_, err := NewRSASigner(&rsa.PrivateKey{}, crypto.SHA1)
	assert.Error(t, err)
}

func Test_NewRSASigner_NilPrivateKey(t *testing.T) {
	_, err := NewRSASigner(nil, crypto.SHA256)
	assert.Error(t, err)
}

func Test_NewRSASigner(t *testing.T) {
	_, err := NewRSASigner(rsaPrivateKey(), crypto.SHA256)
	assert.NoError(t, err)
}

func Test_RSASigner_String(t *testing.T) {
	rs, err := NewRSASigner(rsaPrivateKey(), crypto.SHA256)
	require.NoError(t, err)

	assert.Equal(t, "rsa-sha256", rs.String())
}

func Test_RSASigner_SignSHA256(t *testing.T) {
	rs, err := NewRSASigner(rsaPrivateKey(), crypto.SHA256)
	require.NoError(t, err)

	content := []byte("test")
	// expected generated using (echo -n -e "test" | openssl dgst -sha256 -sign test-certificates/rsa.pem | openssl base64)
	expected := "SZeXeLqG2DNAo2QGVGnfKi684YGXCkgWGtMJQCJ49At6H2LqRLFHsHeTz619rFtYw509dh6ORrxUggQPIT7+UIhFLd3jQWNBIj+skVPctGzuF3vZgYI1bTsjB8fiZumoZF59kDdaPBQ+68s6FvjvegC6w2wbnYUGrhUb6toGamgf7yLsauKT2R8QoVji+YDd31VIbb7ulYAHl452lD8u23uNK4oP/EXtGaXfrXMf/RLzRjgi+JsiZLL6T2ah01tuSorZnFUlcNM8+cYC9Erim9wYO3zOhPiiZhiklltKnuP7OZ/OX6sl/woMM0tRCf2S+ar6N3ru56d574LtNe9/Rg=="

	output, err := rs.Sign(rand.Reader, content)
	require.NoError(t, err)
	assert.Equal(t, base64.StdEncoding.EncodeToString(output), expected)
}

func Test_RSASigner_SignSHA512(t *testing.T) {
	rs, err := NewRSASigner(rsaPrivateKey(), crypto.SHA512)
	require.NoError(t, err)

	content := []byte("test")
	// expected generated using (echo -n -e "test" | openssl dgst -sha512 -sign test-certificates/rsa.pem | openssl base64)
	expected := "LnDwf9ImqyKY8ZbQFJMh3NwfbvPBl737FPr7kn7TngH7eggiLq7cHagqxXXuUaPCfdwF7oAXOdLriRFkeIgtyTgx11zq6l7uCq/M9jDpaKGUqNBau9Trt3viZ2swpVKG/UZMIYCxPFWLC+yaocsAvdZiHcLXWBlqPB6sFYNIWGlfsGvpUVHx82qsEg9LffhDFVhJ5FAslkKuG6j1aba0gMIBvD9plXN8CR0YQJRR6RmKiFTFUREjhs2ULdi6O/dnyxy95XyWv1ROixatpMXX4mrBCr/ZjnJuQy05OU8S2qYZDNAe0Q9RsPpFQc7BIsGxtvTDlYVuO83HrvC0qz4s7g=="

	output, err := rs.Sign(rand.Reader, content)
	require.NoError(t, err)
	assert.Equal(t, base64.StdEncoding.EncodeToString(output), expected)
}

func Fuzz_RSASigner_SignSHA256(f *testing.F) {
	rs, _ := NewRSASigner(rsaPrivateKey(), crypto.SHA256)

	f.Add([]byte("test"))
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := rs.Sign(rand.Reader, b)
		if err != nil || base64.StdEncoding.EncodeToString(out) == "" {
			t.Errorf("Input: %v\nOutput: %v\nError:%v", b, out, err)
		}
	})
}

func Fuzz_RSASigner_SignSHA512(f *testing.F) {
	rs, _ := NewRSASigner(rsaPrivateKey(), crypto.SHA512)

	f.Add([]byte("test"))
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := rs.Sign(rand.Reader, b)
		if err != nil || base64.StdEncoding.EncodeToString(out) == "" {
			t.Errorf("Input: %v\nOutput: %v\nError:%v", b, out, err)
		}
	})
}

func rsaPrivateKey() *rsa.PrivateKey {
	keyBytes, _ := os.ReadFile("./test-certificates/rsa.pem")
	decoded, _ := pem.Decode(keyBytes)
	pk, _ := x509.ParsePKCS1PrivateKey(decoded.Bytes)
	return pk
}
