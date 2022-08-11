package httpsignatures

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

const (
	digestSignatureStringHeader = "digest"
)

var (
	keyIDRegex     = regexp.MustCompile(`keyId="([^"]+)"`)
	algorithmRegex = regexp.MustCompile(`algorithm="([^"]+)"`)
	headersRegex   = regexp.MustCompile(`headers="([^"]+)"`)
	signatureRegex = regexp.MustCompile(`signature="([^"]+)"`)
)

// MessageVerifier verifies the signatures on messages.
type MessageVerifier struct {
	requiredHeaders []string
	keyIDMetadataFn KeyIDMetadata
}

type messageAttributes struct {
	req              *http.Request
	keyID            string
	algorithm        string
	signatureHeaders []string
	signature        string
}

// KeyIDMetadata function type for providing a public key and optional expected hashing algorithm
// from a keyId in a signature.
type KeyIDMetadata func(keyID string) (crypto.PublicKey, crypto.Hash, error)

// NewMessageVerifier creates a new instance of MessageVerifier.
func NewMessageVerifier(requiredHeaders []string, keyIDMetadataFn KeyIDMetadata) *MessageVerifier {
	return &MessageVerifier{
		requiredHeaders: requiredHeaders,
		keyIDMetadataFn: keyIDMetadataFn,
	}
}

// Verify verifies the signature on the request. If the body is not empty and
// the signature contains `digest`, the digest is also validated against the body.
func (mv *MessageVerifier) VerifyRequest(req *http.Request) error {
	ma := &messageAttributes{
		req: req,
	}

	if err := ma.extractSignature(); err != nil {
		return NewVerificationError("failed to extract signature from headers", err)
	}

	if contains(ma.signatureHeaders, digestSignatureStringHeader) {
		if err := ma.verifyDigest(); err != nil {
			return NewVerificationError("failed to verify digest", err)
		}
	}

	if err := ma.validateRequiredHeaders(mv.requiredHeaders); err != nil {
		return NewVerificationError("required headers not found in signature", err)
	}

	publicKey, algo, err := mv.keyIDMetadataFn(ma.keyID)
	if err != nil {
		return NewVerificationError("failed to retrieve public key from keyId", err)
	}

	verifier, err := newVerifier(publicKey, algo, ma.algorithm)
	if err != nil {
		return NewVerificationError("failed to create signature verifier", err)
	}

	if err := ma.verifySignature(verifier); err != nil {
		return NewVerificationError("failed to verify signature", err)
	}

	return nil
}

// extractSignature splits the signature into its composite parts and populates them in
// messageAttributes.
func (ma *messageAttributes) extractSignature() error {
	signatureString, err := determineSignature(ma.req.Header)
	if err != nil {
		return err
	}

	keyID, algorithm, headers, signature, err := parseSignatureString(signatureString)
	if err != nil {
		return err
	}

	ma.keyID = keyID
	ma.algorithm = algorithm
	ma.signatureHeaders = headers
	ma.signature = signature

	return nil
}

// verifyDigest ensures the header value is of the correct format and then generates a digest
// of the body and compares it against the digest in the header.
func (ma *messageAttributes) verifyDigest() error {
	digest := ma.req.Header.Get(digestHeaderKey)

	components := strings.SplitN(digest, equalDelimiter, 2)
	if len(components) != 2 || components[1] == "" {
		return NewDataError(fmt.Sprintf("expected digest to have 2 components when splitting on '=', but found %v", len(components)), nil)
	}

	cryptoHash, err := getHashingAlgorithmByDigestKey(components[0])
	if err != nil {
		return err
	}

	body, err := readBody(ma.req)
	if err != nil {
		return NewDataError("failed to read request body", err)
	}

	expectedDigest, err := generateDigest(cryptoHash.FetchHasher(), body)
	if err != nil {
		return err
	}

	if expectedDigest != components[1] {
		return NewDataError(fmt.Sprintf(`digest "%s" did not match expected digest "%s"`, digest, expectedDigest), nil)
	}

	return nil
}

// validateRequiredHeaders ensures all required headers exist in the signature headers.
func (ma *messageAttributes) validateRequiredHeaders(requiredHeaders []string) error {
	// if there are no required headers, don't do anything.
	if len(requiredHeaders) == 0 {
		return nil
	}

	headers := map[string]struct{}{}

	for _, header := range ma.signatureHeaders {
		headers[header] = struct{}{}
	}

	missingHeaders := []string{}

	for _, header := range requiredHeaders {
		if _, ok := headers[header]; !ok {
			missingHeaders = append(missingHeaders, header)
		}
	}

	if len(missingHeaders) > 0 {
		return NewSignatureError(fmt.Sprintf("signature missing required headers: %s", strings.Join(missingHeaders, ", ")), nil)
	}

	return nil
}

// verifySignature verifies that the signature is valid for the headers.
func (ma *messageAttributes) verifySignature(verifier Verifier) error {
	signatureSum, err := base64.StdEncoding.DecodeString(ma.signature)
	if err != nil {
		return NewDataError("failed base64 decoding signature", err)
	}

	signatureString, err := generateSignatureString(ma.req, ma.signatureHeaders)
	if err != nil {
		return err
	}

	return verifier.Verify(signatureSum, signatureString)
}

// getHashingAlgorithmByDigestKey finds the hashing algorithm for the given key in a digest header value.
func getHashingAlgorithmByDigestKey(digestKey string) (*HashingAlgorithm, error) {
	switch digestKey {
	case crypto.SHA256.String():
		return fetchCryptoHash(crypto.SHA256)
	case crypto.SHA512.String():
		return fetchCryptoHash(crypto.SHA512)
	}

	return nil, NewDataError(fmt.Sprintf("digest algorithm could not be found or is not supported: %s", digestKey), nil)
}

// determineSignature determines whether the signature belongs in the Signature or the
// Authorization header. If both or neither contain a signature then an error is returned.
// Signatures that contains a duplicate field, e.g. 2 fields named 'keyId', should not be
// evaluated as valid.
func determineSignature(headers http.Header) (string, error) {
	validSignatureHeader := false
	validAuthorizationHeader := false

	signatureHeader := headers.Get(string(Signature))
	if signatureHeader != "" {
		validSignatureHeader = strings.Count(signatureHeader, signatureHeaderKeyIDKey) == 1 &&
			strings.Count(signatureHeader, signatureHeaderAlgorithmKey) == 1 &&
			strings.Count(signatureHeader, signatureHeaderHeadersKey) == 1 &&
			strings.Count(signatureHeader, signatureHeaderSignatureKey) == 1
	}

	authorizationHeader := headers.Get(string(Authorization))
	if authorizationHeader != "" {
		validAuthorizationHeader = strings.Count(authorizationHeader, signatureHeaderKeyIDKey) == 1 &&
			strings.Count(authorizationHeader, signatureHeaderAlgorithmKey) == 1 &&
			strings.Count(authorizationHeader, signatureHeaderHeadersKey) == 1 &&
			strings.Count(authorizationHeader, signatureHeaderSignatureKey) == 1
	}

	switch {
	case validSignatureHeader && validAuthorizationHeader:
		return "", NewValidationError("both Signature and Authorization headers contain signatures, cannot proceed due to ambiguity")
	case validSignatureHeader:
		return signatureHeader, nil
	case validAuthorizationHeader:
		return authorizationHeader, nil
	}

	return "", NewValidationError("neither Signature nor Authorization headers contain a valid signature")
}

// parseSignatureString parses the signature string out into its individual attributes.
// If any part is not present in the correct format, an error is returned.
func parseSignatureString(signatureString string) (keyID, algorithm string, headers []string, signature string, err error) {
	keyIDMatch := keyIDRegex.FindStringSubmatch(signatureString)
	if keyIDMatch == nil || len(keyIDMatch) == 1 {
		err = NewDataError("keyId could not be found in signature string", nil)
		return
	}
	keyID = keyIDMatch[1]

	algorithmMatch := algorithmRegex.FindStringSubmatch(signatureString)
	if algorithmMatch == nil {
		err = NewDataError("algorithm could not be found in signature string", nil)
		return
	}
	algorithm = algorithmMatch[1]

	headersMatch := headersRegex.FindStringSubmatch(signatureString)
	if headersMatch == nil {
		err = NewDataError("headers could not be found in signature string", nil)
		return
	}
	headers = strings.Split(headersMatch[1], " ")

	signatureMatch := signatureRegex.FindStringSubmatch(signatureString)
	if signatureMatch == nil {
		err = NewDataError("signature could not be found in signature string", nil)
		return
	}
	signature = signatureMatch[1]

	return
}

func contains[T comparable](s []T, o T) bool {
	for _, item := range s {
		if o == item {
			return true
		}
	}
	return false
}
