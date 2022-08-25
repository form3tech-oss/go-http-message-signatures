package httpsignatures

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testSigner struct {
	shouldError bool
}

func (ts *testSigner) Sign(rand io.Reader, content []byte) ([]byte, error) {
	if ts.shouldError {
		return nil, errors.New("error")
	}
	return []byte("signature"), nil
}

func (ts *testSigner) String() string {
	return "test"
}

type generateSignatureStringTestCase struct {
	title                   string
	signatureHeaders        []string
	request                 *http.Request
	expectedSignatureString []string
	errorType               error
}

func (w *generateSignatureStringTestCase) test(t *testing.T) {
	signatureString, err := generateSignatureString(w.request, w.signatureHeaders)
	if w.errorType != nil {
		assert.ErrorAs(t, err, &w.errorType)
		return
	}

	assert.NoError(t, err)
	assert.Equal(t, strings.Join(w.expectedSignatureString, "\n"), string(signatureString))
}

func Test_generateSignatureString(t *testing.T) {
	testCases := []generateSignatureStringTestCase{
		{
			title:            "All standard headers",
			signatureHeaders: []string{"date", "host"},
			request: &http.Request{
				Header: map[string][]string{
					"Date": {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host": {"example.org"},
				},
			},
			expectedSignatureString: []string{
				"date: Fri, 29 Jul 2022 13:23:35 GMT",
				"host: example.org",
			},
		},
		{
			title:            "Standard headers with more than value",
			signatureHeaders: []string{"date", "host"},
			request: &http.Request{
				Header: map[string][]string{
					"Date": {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host": {"example.org", "example2.org"},
				},
			},
			expectedSignatureString: []string{
				"date: Fri, 29 Jul 2022 13:23:35 GMT",
				"host: example.org, example2.org",
			},
		},
		{
			title:            "Request target special case included",
			signatureHeaders: []string{"(request-target)", "date", "host"},
			request: &http.Request{
				Method: "GET",
				URL: &url.URL{
					Path: "/example",
				},
				Header: map[string][]string{
					"Date": {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host": {"example.org"},
				},
			},
			expectedSignatureString: []string{
				"(request-target): get /example",
				"date: Fri, 29 Jul 2022 13:23:35 GMT",
				"host: example.org",
			},
		},
		{
			title:            "Request target with query special case included",
			signatureHeaders: []string{"(request-target)", "date", "host"},
			request: &http.Request{
				Method: "GET",
				URL: &url.URL{
					Path:     "/example",
					RawQuery: "query",
				},
				Header: map[string][]string{
					"Date": {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host": {"example.org"},
				},
			},
			expectedSignatureString: []string{
				"(request-target): get /example?query",
				"date: Fri, 29 Jul 2022 13:23:35 GMT",
				"host: example.org",
			},
		},
		{
			title:            "Missing header errors",
			signatureHeaders: []string{"date", "host"},
			request: &http.Request{
				Header: map[string][]string{
					"Date": {"Fri, 29 Jul 2022 13:23:35 GMT"},
				},
			},
			errorType: &DataError{},
		},
		{
			title:            "Additional headers are not included",
			signatureHeaders: []string{"date", "host"},
			request: &http.Request{
				Header: map[string][]string{
					"Date":            {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":            {"example.org"},
					"Accept-Encoding": {"gzip"},
				},
			},
			expectedSignatureString: []string{
				"date: Fri, 29 Jul 2022 13:23:35 GMT",
				"host: example.org",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, tc.test)
	}
}

func Test_setSignatureHeader(t *testing.T) {
	ms := &MessageSigner{
		publicKeyID:  "abc",
		targetHeader: Authorization,
		signer:       &testSigner{},
	}

	req := &http.Request{
		Header: map[string][]string{},
	}

	ms.setSignatureHeader(req, []string{"(request-target)", "date", "host"}, []byte("a very good signature"))

	expected := `Signature keyId="abc",algorithm="test",headers="(request-target) date host",signature="YSB2ZXJ5IGdvb2Qgc2lnbmF0dXJl"`
	assert.Equal(t, expected, req.Header.Get("Authorization"))
}

func Test_digestMessageFormat(t *testing.T) {
	algo := "SHA-256"
	digest := "digest"

	expected := fmt.Sprintf("%s=%s", algo, digest)
	assert.Equal(t, expected, digestMessageFormat(algo, digest))
}

func Test_readBody(t *testing.T) {
	body := []byte("body")

	req := &http.Request{
		Body: io.NopCloser(bytes.NewBuffer(body)),
	}

	actualBody, err := readBody(req)
	// correct body is returned
	assert.NoError(t, err)
	assert.Equal(t, body, actualBody)

	reqBody, err := io.ReadAll(req.Body)
	// body is re-written to request
	assert.NoError(t, err)
	assert.Equal(t, body, reqBody)
}

func Test_readBody_Nil(t *testing.T) {
	req := &http.Request{}
	body, err := readBody(req)
	assert.NoError(t, err)
	assert.Nil(t, body)
}

type errorReadCloser struct {
	readError  bool
	closeError bool
}

func (e *errorReadCloser) Read(p []byte) (n int, err error) {
	if e.readError {
		return 0, errors.New("error")
	}
	return 0, io.EOF
}

func (e *errorReadCloser) Close() error {
	if e.closeError {
		return errors.New("error")
	}
	return nil
}

func Test_readBody_ReadAllError(t *testing.T) {
	req := &http.Request{
		Body: &errorReadCloser{
			readError: true,
		},
	}
	_, err := readBody(req)
	assert.Error(t, err)
}

func Test_readBody_CloseError(t *testing.T) {
	req := &http.Request{
		Body: &errorReadCloser{
			closeError: true,
		},
	}
	_, err := readBody(req)
	assert.Error(t, err)
}

func Test_generateDigest(t *testing.T) {
	testCases := []struct {
		title    string
		algo     crypto.Hash
		input    []byte
		expected string
	}{
		{
			title:    "sha256",
			algo:     crypto.SHA256,
			input:    []byte("test"),
			expected: "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=",
		},
		{
			title:    "sha512",
			algo:     crypto.SHA512,
			input:    []byte("test"),
			expected: "7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			cryptoHash, err := fetchCryptoHash(tc.algo)
			require.NoError(t, err)
			digest, err := generateDigest(cryptoHash.FetchHasher(), tc.input)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, digest)
		})
	}
}

func Test_NewMessageSigner_BadCryptoHash(t *testing.T) {
	_, err := NewMessageSigner(crypto.SHA1, nil, "", Authorization)
	assert.Error(t, err)
}

type signMessageTestCase struct {
	title             string
	req               *http.Request
	targetHeader      TargetHeader
	signatureHeaders  []string
	algo              crypto.Hash
	signer            Signer
	publicKeyID       string
	expectedSignature string
	expectedDigest    string
	errorExpected     bool
}

func (s *signMessageTestCase) test(t *testing.T) {
	ms, err := NewMessageSigner(s.algo, s.signer, s.publicKeyID, s.targetHeader)
	require.NoError(t, err)
	req, err := ms.SignRequest(s.req, s.signatureHeaders)
	if s.errorExpected {
		assert.Error(t, err)
		return
	}

	assert.NoError(t, err)
	assert.Equal(t, s.expectedSignature, req.Header.Get(string(s.targetHeader)))

	// We always add digest, so check it's correct
	assert.Equal(t, fmt.Sprintf("%s=%s", s.algo.String(), s.expectedDigest), req.Header.Get("Digest"))
}

func Test_SignMessage(t *testing.T) {
	testCases := []signMessageTestCase{
		{
			title: "Request signature is correct",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date": {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host": {"example.org"},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			targetHeader:      Authorization,
			signatureHeaders:  []string{"(request-target)", "date", "host", "digest"},
			algo:              crypto.SHA256,
			signer:            &testSigner{},
			publicKeyID:       "abc",
			expectedSignature: `Signature keyId="abc",algorithm="test",headers="(request-target) date host digest",signature="c2lnbmF0dXJl"`,
			expectedDigest:    "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=",
		},
		{
			title: "No signature headers",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date": {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host": {"example.org"},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			targetHeader:     Authorization,
			signatureHeaders: []string{},
			algo:             crypto.SHA256,
			signer:           &testSigner{},
			publicKeyID:      "abc",
			errorExpected:    true,
		},
		{
			title: "Digest added, even when not used in signature",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date": {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host": {"example.org"},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			targetHeader:      Authorization,
			signatureHeaders:  []string{"(request-target)", "date", "host"},
			algo:              crypto.SHA256,
			signer:            &testSigner{},
			publicKeyID:       "abc",
			expectedSignature: `Signature keyId="abc",algorithm="test",headers="(request-target) date host",signature="c2lnbmF0dXJl"`,
			expectedDigest:    "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=",
		},
		{
			title: "Header not present",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date": {"Fri, 29 Jul 2022 13:23:35 GMT"},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			targetHeader:     Authorization,
			signatureHeaders: []string{"(request-target)", "date", "host"},
			algo:             crypto.SHA256,
			signer:           &testSigner{},
			publicKeyID:      "abc",
			errorExpected:    true,
		},
		{
			title: "Signer error",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date": {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host": {"example.org"},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			targetHeader:     Authorization,
			signatureHeaders: []string{"(request-target)", "date", "host"},
			algo:             crypto.SHA256,
			signer: &testSigner{
				shouldError: true,
			},
			publicKeyID:   "abc",
			errorExpected: true,
		},
		{
			title: "Request signature is correct when setting Signature header",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date": {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host": {"example.org"},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			targetHeader:      Signature,
			signatureHeaders:  []string{"(request-target)", "date", "host", "digest"},
			algo:              crypto.SHA256,
			signer:            &testSigner{},
			publicKeyID:       "abc",
			expectedSignature: `keyId="abc",algorithm="test",headers="(request-target) date host digest",signature="c2lnbmF0dXJl"`,
			expectedDigest:    "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, tc.test)
	}
}

func Fuzz_SignMessage_RSASigner(f *testing.F) {
	rs, _ := NewRSASigner(rsaPrivateKey(), crypto.SHA512)
	defaultHeaders := []string{"(request-target)", "date", "host"}

	f.Add("6A226629-556F-4EFB-8206-77E32FCE6BA9", []byte("test"))
	f.Fuzz(func(t *testing.T, keyID string, body []byte) {
		ms, _ := NewMessageSigner(crypto.SHA256, rs, keyID, Authorization)
		req := &http.Request{
			Method: "POST",
			URL: &url.URL{
				Path: "/example",
			},
			Header: http.Header{
				"Date": {"Fri, 29 Jul 2022 13:23:35 GMT"},
				"Host": {"example.org"},
			},
			Body: io.NopCloser(bytes.NewBuffer(body)),
		}
		headers := defaultHeaders
		if len(body) > 0 {
			headers = append(headers, "digest")
		}

		out, err := ms.SignRequest(req, headers)
		if err != nil || out.Header.Get("Authorization") == "" || (len(body) > 0 && out.Header.Get("Digest") == "") {
			t.Errorf("KeyID: %s\nBody: %v\nOutputHeaders: %v\nError: %v", keyID, body, out.Header, err)
		}
	})
}
