package httpsignatures

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/textproto"
	"strings"
)

const (
	digestHeaderKey = "Digest"

	signatureHeaderKeyIDKey     = "keyId"
	signatureHeaderAlgorithmKey = "algorithm"
	signatureHeaderHeadersKey   = "headers"
	signatureHeaderSignatureKey = "signature"

	signatureStringDelimiter = ": "
	spaceSeparator           = " "
	headerValueSeparator     = ", "
	newline                  = "\n"
	doubleQuote              = `"`
	commaDelimiter           = ","
	equalDelimiter           = "="
)

// TargetHeader is the header that the signature should be populated on.
type TargetHeader string

const (
	Signature     TargetHeader = "Signature"
	Authorization TargetHeader = "Authorization"

	authorizationHeaderPrefix string = "Signature "
)

// valuePrefix returns a string that should be prefixed to the header value for the given target.
func (s TargetHeader) valuePrefix() string {
	switch s {
	case Authorization:
		return authorizationHeaderPrefix
	case Signature:
		return ""
	default:
		return ""
	}
}

const (
	// RequestTarget is the special case header that can be included in the signature string.
	RequestTarget = "(request-target)"
)

// signatureStringSpecialCase specifies format functions for designated headers.
// More information can be found in section 2.3 [here](https://www.ietf.org/archive/id/draft-cavage-http-signatures-12.txt).
func fetchSignatureStringSpecialCase(s string) func(r *http.Request, b *bytes.Buffer) error {
	switch s {
	case RequestTarget:
		return addRequestTarget
	default:
		return nil
	}
}

// MessageSigner is used to sign HTTP messages.
type MessageSigner struct {
	// algo is the chosen crypto algorithm.
	algo *HashingAlgorithm
	// signer will be used to sign the message.
	signer Signer
	// publicKeyID is the ID that can be used to look up the public key on the receiving server.
	publicKeyID string
	// targetHeader defines which header to populate on the request with the signature.
	targetHeader TargetHeader
}

// NewMessageSigner checks that the given algorithm is valid and returns a new MessageSigner.
func NewMessageSigner(algo crypto.Hash, signer Signer, publicKeyID string, targetHeader TargetHeader) (*MessageSigner, error) {
	cryptoHash, err := fetchCryptoHash(algo)
	if err != nil {
		return nil, NewInitialisationError("could not retrieve crypto hash", err)
	}

	return &MessageSigner{
		algo:         cryptoHash,
		publicKeyID:  publicKeyID,
		signer:       signer,
		targetHeader: targetHeader,
	}, nil
}

// SignRequest method signs provided http.Request
// signatureHeaders is a list of header names that specifies which of them (together with their values) will be signed. At least one is required.
func (ms *MessageSigner) SignRequest(req *http.Request, signatureHeaders []string) (*http.Request, error) {
	if len(signatureHeaders) == 0 {
		return nil, NewValidationError("no signature headers set, at least one should be specified")
	}

	body, err := readBody(req)
	if err != nil {
		return nil, NewDataError("failed to read request body", err)
	}

	if len(body) != 0 {
		digest, err := generateDigest(ms.algo.FetchHasher(), body)
		if err != nil {
			return nil, err
		}

		req.Header.Set(digestHeaderKey, digestMessageFormat(ms.algo.Hash.String(), digest))
	}

	signature, err := ms.generateSignature(req, signatureHeaders)
	if err != nil {
		return nil, NewSigningError("failed to sign request", err)
	}

	ms.setSignatureHeader(req, signatureHeaders, signature)

	return req, nil
}

// digestMessageFormat produces a header value for the given digest.
func digestMessageFormat(algo string, digest string) string {
	return algo + equalDelimiter + digest
}

// readBody safely reads the body of the request and sets it back so there are no
// side effects of using this function.
func readBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, NewInternalError("error reading request body", err)
	}
	// Close to overwrite
	err = req.Body.Close()
	if err != nil {
		return nil, err
	}

	// write body back, so it can be sent further
	req.Body = io.NopCloser(bytes.NewBuffer(body))

	return body, nil
}

// generateDigest generates a digest of the request body using the configured algorithm and base64 encodes it.
func generateDigest(hasher hash.Hash, requestBody []byte) (string, error) {
	_, err := hasher.Write(requestBody)
	if err != nil {
		return "", NewInternalError("error writing digest", err)
	}

	return base64.StdEncoding.EncodeToString(hasher.Sum(nil)), nil
}

// generateSignature generates a signature of the request.
func (ms *MessageSigner) generateSignature(req *http.Request, signatureHeaders []string) ([]byte, error) {
	signatureString, err := generateSignatureString(req, signatureHeaders)
	if err != nil {
		return nil, err
	}

	return ms.signer.Sign(rand.Reader, signatureString)
}

// writeSignatureString creates a new signature string from the required headers.
func generateSignatureString(req *http.Request, signatureHeaders []string) ([]byte, error) {
	var b bytes.Buffer
	for i, header := range signatureHeaders {
		header = strings.ToLower(header)
		if fn := fetchSignatureStringSpecialCase(header); fn != nil {
			err := fn(req, &b)
			if err != nil {
				return nil, err
			}
		} else {
			b.WriteString(header)
			b.WriteString(signatureStringDelimiter)
			headerValues := req.Header.Values(textproto.CanonicalMIMEHeaderKey(header))
			if len(headerValues) == 0 {
				return nil, NewDataError(fmt.Sprintf("required signature string header not present: %s", header), nil)
			}
			b.WriteString(strings.TrimSpace(strings.Join(headerValues, headerValueSeparator)))
		}

		if i < len(signatureHeaders)-1 {
			b.WriteString(newline)
		}
	}

	return b.Bytes(), nil
}

// setSignatureHeader generates the header value and assigns it to the Authorization header.
func (ms *MessageSigner) setSignatureHeader(req *http.Request, signatureHeaders []string, signature []byte) {
	var b bytes.Buffer
	b.WriteString(ms.targetHeader.valuePrefix())

	// write public key ID
	b.WriteString(signatureHeaderKeyIDKey)
	b.WriteString(equalDelimiter)
	b.WriteString(doubleQuote)
	b.WriteString(ms.publicKeyID)
	b.WriteString(doubleQuote)
	b.WriteString(commaDelimiter)

	// write algorithm
	b.WriteString(signatureHeaderAlgorithmKey)
	b.WriteString(equalDelimiter)
	b.WriteString(doubleQuote)
	b.WriteString(ms.signer.String())
	b.WriteString(doubleQuote)
	b.WriteString(commaDelimiter)

	// write headers
	b.WriteString(signatureHeaderHeadersKey)
	b.WriteString(equalDelimiter)
	b.WriteString(doubleQuote)
	b.WriteString(strings.Join(signatureHeaders, spaceSeparator))
	b.WriteString(doubleQuote)
	b.WriteString(commaDelimiter)

	// write signature
	b.WriteString(signatureHeaderSignatureKey)
	b.WriteString(equalDelimiter)
	b.WriteString(doubleQuote)
	b.WriteString(base64.StdEncoding.EncodeToString(signature))
	b.WriteString(doubleQuote)

	req.Header.Set(string(ms.targetHeader), b.String())
}

// addRequestTarget adds the request target string to the bytes buffer for signature string.
func addRequestTarget(req *http.Request, b *bytes.Buffer) error {
	b.WriteString(RequestTarget)
	b.WriteString(signatureStringDelimiter)
	b.WriteString(strings.ToLower(req.Method))
	b.WriteString(spaceSeparator)
	b.WriteString(req.URL.Path)

	if req.URL.RawQuery != "" {
		b.WriteString("?")
		b.WriteString(req.URL.RawQuery)
	}

	return nil
}
