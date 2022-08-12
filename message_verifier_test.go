package httpsignatures

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type verifyRequestTestCase struct {
	title           string
	req             *http.Request
	signature       string
	requiredHeaders []string
	keyIDMetadataFn KeyIDMetadata
	errorExpected   bool
}

func (tc *verifyRequestTestCase) test(t *testing.T) {
	mv := NewMessageVerifier(tc.requiredHeaders, tc.keyIDMetadataFn)
	err := mv.VerifyRequest(tc.req)
	if tc.errorExpected {
		assert.Error(t, err)
	} else {
		assert.NoError(t, err)
	}
}

func Test_VerifyRequest(t *testing.T) {
	testCases := []verifyRequestTestCase{
		{
			title: "Valid signature",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			// signature generated with (echo -n "(request-target): post /example\ndate: Fri, 29 Jul 2022 13:23:35 GMT\nhost: example.org\ndigest: SHA-256=n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=" | openssl dgst -sha256 -sign test-certificates/rsa.pem | openssl base64)
			signature: `keyId="abc",algorithm="rsa-sha256",headers="(request-target) date host digest",signature="jFpHNN2jW4MTZnZGxm38qx6TqLJCeHEnKW7NhujN6VL7mFbZt6MZ1UcJS/YUYKLnFw1PBbvcOYjTarf2fCtIsCrHKCcYaSaK33L9HrcqoDH/ykOCd57TcNggrFCiqV4sOdjXgFj8Bi7fJbK0QCbIKv03YxBAUiUHArnTP6ANpRiAIyzQxGjGTFjgd2ENgU7Luf346xHdblbwecvJvabmN63mf9a/WFZ21JLERLH2PtAlcbmK43trIjnvHwGeSbi7Pd0xpiXXlhyG+iIdLqbszKjGvYd2cdK4nSfjJhhslA8KS8q5DVp0kJLZKfTbtAVI3mrmVyRAH0ZAa7SXqZQlcQ=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   false,
		},
		{
			title: "Invalid signature",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",algorithm="rsa-sha256",headers="(request-target) date host digest",signature="not a valid signature"`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
		{
			title: "Required headers not present in signature",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",algorithm="rsa-sha256",headers="(request-target) date digest",signature="Y/KN6QfVPYUJbgsiT/nmCrlxKFdBYdU5M+UjGEHzQ4P18L2l4L9c5UakQKQTDTaYfCcASRLNQ3qidckdkP1Anlv6Th9oMy5eKy8QNu9jx4RplhkGvUxrZX8WG5g7urH3NoTco/MnhUULOwz8kjSj1O86VxmsRaFPdj+iebjxQgoOhYMSLjI1rFSJLFvl06pSOspZuFgZbfnWEzQUjPZXm00+/ViaYGWkmNamxCH2g4GLdSSOJBDE9HGNsYCsa9Lu41uhkrf3WwlLF56DOnVUfGNSup9L29OkDf9R6ejftCTNRjSIM2JGnJuaABnjJd793lANxOZrejJK5Uqva1ZWOA=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
		{
			title: "header missing from request",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Digest": {"SHA-256=n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",algorithm="rsa-sha256",headers="(request-target) date host digest",signature="Y/KN6QfVPYUJbgsiT/nmCrlxKFdBYdU5M+UjGEHzQ4P18L2l4L9c5UakQKQTDTaYfCcASRLNQ3qidckdkP1Anlv6Th9oMy5eKy8QNu9jx4RplhkGvUxrZX8WG5g7urH3NoTco/MnhUULOwz8kjSj1O86VxmsRaFPdj+iebjxQgoOhYMSLjI1rFSJLFvl06pSOspZuFgZbfnWEzQUjPZXm00+/ViaYGWkmNamxCH2g4GLdSSOJBDE9HGNsYCsa9Lu41uhkrf3WwlLF56DOnVUfGNSup9L29OkDf9R6ejftCTNRjSIM2JGnJuaABnjJd793lANxOZrejJK5Uqva1ZWOA=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
		{
			title: "Different signature hash used to the one that is required of the keyId",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",algorithm="rsa-sha256",headers="(request-target) date host digest",signature="jFpHNN2jW4MTZnZGxm38qx6TqLJCeHEnKW7NhujN6VL7mFbZt6MZ1UcJS/YUYKLnFw1PBbvcOYjTarf2fCtIsCrHKCcYaSaK33L9HrcqoDH/ykOCd57TcNggrFCiqV4sOdjXgFj8Bi7fJbK0QCbIKv03YxBAUiUHArnTP6ANpRiAIyzQxGjGTFjgd2ENgU7Luf346xHdblbwecvJvabmN63mf9a/WFZ21JLERLH2PtAlcbmK43trIjnvHwGeSbi7Pd0xpiXXlhyG+iIdLqbszKjGvYd2cdK4nSfjJhhslA8KS8q5DVp0kJLZKfTbtAVI3mrmVyRAH0ZAa7SXqZQlcQ=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(crypto.SHA512, nil),
			errorExpected:   true,
		},
		{
			title: "keyId function returns error",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",algorithm="rsa-sha256",headers="(request-target) date host digest",signature="jFpHNN2jW4MTZnZGxm38qx6TqLJCeHEnKW7NhujN6VL7mFbZt6MZ1UcJS/YUYKLnFw1PBbvcOYjTarf2fCtIsCrHKCcYaSaK33L9HrcqoDH/ykOCd57TcNggrFCiqV4sOdjXgFj8Bi7fJbK0QCbIKv03YxBAUiUHArnTP6ANpRiAIyzQxGjGTFjgd2ENgU7Luf346xHdblbwecvJvabmN63mf9a/WFZ21JLERLH2PtAlcbmK43trIjnvHwGeSbi7Pd0xpiXXlhyG+iIdLqbszKjGvYd2cdK4nSfjJhhslA8KS8q5DVp0kJLZKfTbtAVI3mrmVyRAH0ZAa7SXqZQlcQ=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, errors.New("error")),
			errorExpected:   true,
		},
		{
			title: "digest is not valid for request body",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=not_valid"},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",algorithm="rsa-sha256",headers="(request-target) date host digest",signature="jFpHNN2jW4MTZnZGxm38qx6TqLJCeHEnKW7NhujN6VL7mFbZt6MZ1UcJS/YUYKLnFw1PBbvcOYjTarf2fCtIsCrHKCcYaSaK33L9HrcqoDH/ykOCd57TcNggrFCiqV4sOdjXgFj8Bi7fJbK0QCbIKv03YxBAUiUHArnTP6ANpRiAIyzQxGjGTFjgd2ENgU7Luf346xHdblbwecvJvabmN63mf9a/WFZ21JLERLH2PtAlcbmK43trIjnvHwGeSbi7Pd0xpiXXlhyG+iIdLqbszKjGvYd2cdK4nSfjJhhslA8KS8q5DVp0kJLZKfTbtAVI3mrmVyRAH0ZAa7SXqZQlcQ=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
		{
			title: "signature missing keyId",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=not_valid"},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `algorithm="rsa-sha256",headers="(request-target) date host digest",signature="jFpHNN2jW4MTZnZGxm38qx6TqLJCeHEnKW7NhujN6VL7mFbZt6MZ1UcJS/YUYKLnFw1PBbvcOYjTarf2fCtIsCrHKCcYaSaK33L9HrcqoDH/ykOCd57TcNggrFCiqV4sOdjXgFj8Bi7fJbK0QCbIKv03YxBAUiUHArnTP6ANpRiAIyzQxGjGTFjgd2ENgU7Luf346xHdblbwecvJvabmN63mf9a/WFZ21JLERLH2PtAlcbmK43trIjnvHwGeSbi7Pd0xpiXXlhyG+iIdLqbszKjGvYd2cdK4nSfjJhhslA8KS8q5DVp0kJLZKfTbtAVI3mrmVyRAH0ZAa7SXqZQlcQ=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
		{
			title: "signature missing algorithm",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=not_valid"},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",headers="(request-target) date host digest",signature="jFpHNN2jW4MTZnZGxm38qx6TqLJCeHEnKW7NhujN6VL7mFbZt6MZ1UcJS/YUYKLnFw1PBbvcOYjTarf2fCtIsCrHKCcYaSaK33L9HrcqoDH/ykOCd57TcNggrFCiqV4sOdjXgFj8Bi7fJbK0QCbIKv03YxBAUiUHArnTP6ANpRiAIyzQxGjGTFjgd2ENgU7Luf346xHdblbwecvJvabmN63mf9a/WFZ21JLERLH2PtAlcbmK43trIjnvHwGeSbi7Pd0xpiXXlhyG+iIdLqbszKjGvYd2cdK4nSfjJhhslA8KS8q5DVp0kJLZKfTbtAVI3mrmVyRAH0ZAa7SXqZQlcQ=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
		{
			title: "signature missing headers",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=not_valid"},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",algorithm="rsa-sha256",signature="jFpHNN2jW4MTZnZGxm38qx6TqLJCeHEnKW7NhujN6VL7mFbZt6MZ1UcJS/YUYKLnFw1PBbvcOYjTarf2fCtIsCrHKCcYaSaK33L9HrcqoDH/ykOCd57TcNggrFCiqV4sOdjXgFj8Bi7fJbK0QCbIKv03YxBAUiUHArnTP6ANpRiAIyzQxGjGTFjgd2ENgU7Luf346xHdblbwecvJvabmN63mf9a/WFZ21JLERLH2PtAlcbmK43trIjnvHwGeSbi7Pd0xpiXXlhyG+iIdLqbszKjGvYd2cdK4nSfjJhhslA8KS8q5DVp0kJLZKfTbtAVI3mrmVyRAH0ZAa7SXqZQlcQ=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
		{
			title: "signature missing signature",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=not_valid"},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",algorithm="rsa-sha256",headers="(request-target) date host digest"`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
		{
			title: "keyId empty",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="",algorithm="rsa-sha256",headers="(request-target) date host digest",signature="jFpHNN2jW4MTZnZGxm38qx6TqLJCeHEnKW7NhujN6VL7mFbZt6MZ1UcJS/YUYKLnFw1PBbvcOYjTarf2fCtIsCrHKCcYaSaK33L9HrcqoDH/ykOCd57TcNggrFCiqV4sOdjXgFj8Bi7fJbK0QCbIKv03YxBAUiUHArnTP6ANpRiAIyzQxGjGTFjgd2ENgU7Luf346xHdblbwecvJvabmN63mf9a/WFZ21JLERLH2PtAlcbmK43trIjnvHwGeSbi7Pd0xpiXXlhyG+iIdLqbszKjGvYd2cdK4nSfjJhhslA8KS8q5DVp0kJLZKfTbtAVI3mrmVyRAH0ZAa7SXqZQlcQ=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
		{
			title: "algorithm empty",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",algorithm="",headers="(request-target) date host digest",signature="jFpHNN2jW4MTZnZGxm38qx6TqLJCeHEnKW7NhujN6VL7mFbZt6MZ1UcJS/YUYKLnFw1PBbvcOYjTarf2fCtIsCrHKCcYaSaK33L9HrcqoDH/ykOCd57TcNggrFCiqV4sOdjXgFj8Bi7fJbK0QCbIKv03YxBAUiUHArnTP6ANpRiAIyzQxGjGTFjgd2ENgU7Luf346xHdblbwecvJvabmN63mf9a/WFZ21JLERLH2PtAlcbmK43trIjnvHwGeSbi7Pd0xpiXXlhyG+iIdLqbszKjGvYd2cdK4nSfjJhhslA8KS8q5DVp0kJLZKfTbtAVI3mrmVyRAH0ZAa7SXqZQlcQ=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
		{
			title: "headers empty",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",algorithm="rsa-sha256",headers="",signature="jFpHNN2jW4MTZnZGxm38qx6TqLJCeHEnKW7NhujN6VL7mFbZt6MZ1UcJS/YUYKLnFw1PBbvcOYjTarf2fCtIsCrHKCcYaSaK33L9HrcqoDH/ykOCd57TcNggrFCiqV4sOdjXgFj8Bi7fJbK0QCbIKv03YxBAUiUHArnTP6ANpRiAIyzQxGjGTFjgd2ENgU7Luf346xHdblbwecvJvabmN63mf9a/WFZ21JLERLH2PtAlcbmK43trIjnvHwGeSbi7Pd0xpiXXlhyG+iIdLqbszKjGvYd2cdK4nSfjJhhslA8KS8q5DVp0kJLZKfTbtAVI3mrmVyRAH0ZAa7SXqZQlcQ=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
		{
			title: "signature empty",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",algorithm="rsa-sha256",headers="(request-target) date host digest",signature="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
		{
			title: "multiple keyId",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",keyId="def",algorithm="rsa-sha256",headers="(request-target) date host digest",signature="jFpHNN2jW4MTZnZGxm38qx6TqLJCeHEnKW7NhujN6VL7mFbZt6MZ1UcJS/YUYKLnFw1PBbvcOYjTarf2fCtIsCrHKCcYaSaK33L9HrcqoDH/ykOCd57TcNggrFCiqV4sOdjXgFj8Bi7fJbK0QCbIKv03YxBAUiUHArnTP6ANpRiAIyzQxGjGTFjgd2ENgU7Luf346xHdblbwecvJvabmN63mf9a/WFZ21JLERLH2PtAlcbmK43trIjnvHwGeSbi7Pd0xpiXXlhyG+iIdLqbszKjGvYd2cdK4nSfjJhhslA8KS8q5DVp0kJLZKfTbtAVI3mrmVyRAH0ZAa7SXqZQlcQ=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
		{
			title: "multiple algorithm",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",algorithm="rsa-sha256",algorithm="rsa-sha512",headers="(request-target) date host digest",signature="jFpHNN2jW4MTZnZGxm38qx6TqLJCeHEnKW7NhujN6VL7mFbZt6MZ1UcJS/YUYKLnFw1PBbvcOYjTarf2fCtIsCrHKCcYaSaK33L9HrcqoDH/ykOCd57TcNggrFCiqV4sOdjXgFj8Bi7fJbK0QCbIKv03YxBAUiUHArnTP6ANpRiAIyzQxGjGTFjgd2ENgU7Luf346xHdblbwecvJvabmN63mf9a/WFZ21JLERLH2PtAlcbmK43trIjnvHwGeSbi7Pd0xpiXXlhyG+iIdLqbszKjGvYd2cdK4nSfjJhhslA8KS8q5DVp0kJLZKfTbtAVI3mrmVyRAH0ZAa7SXqZQlcQ=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
		{
			title: "multiple headers",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",algorithm="rsa-sha256",headers="(request-target)",headers="date host digest",signature="jFpHNN2jW4MTZnZGxm38qx6TqLJCeHEnKW7NhujN6VL7mFbZt6MZ1UcJS/YUYKLnFw1PBbvcOYjTarf2fCtIsCrHKCcYaSaK33L9HrcqoDH/ykOCd57TcNggrFCiqV4sOdjXgFj8Bi7fJbK0QCbIKv03YxBAUiUHArnTP6ANpRiAIyzQxGjGTFjgd2ENgU7Luf346xHdblbwecvJvabmN63mf9a/WFZ21JLERLH2PtAlcbmK43trIjnvHwGeSbi7Pd0xpiXXlhyG+iIdLqbszKjGvYd2cdK4nSfjJhhslA8KS8q5DVp0kJLZKfTbtAVI3mrmVyRAH0ZAa7SXqZQlcQ=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
		{
			title: "multiple signature",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",algorithm="rsa-sha256",headers="(request-target) date host digest",signature="jFpHNN2jW4MTZnZGxm38qx6TqLJCeHEnKW7NhujN6VL7mFbZt6MZ1UcJS/YUYKLnFw1PBbvcOYjTarf2fCtIsCrHKCcYaSaK33L9HrcqoDH/ykOCd57TcNggrFCiqV4sOdjXgFj8Bi7fJbK0QCbIKv03YxBAUiUHArnTP6ANpRiAIyzQxGjGTFjgd2ENgU7Luf346xHdblbwecvJvabmN63mf9a/WFZ21JLERLH2PtAlcbmK43trIjnvHwGeSbi7Pd0xpiXXlhyG+iIdLqbszKjGvYd2cdK4nSfjJhhslA8KS8q5DVp0kJLZKfTbtAVI3mrmVyRAH0ZAa7SXqZQlcQ==",signature="jFpHNN2jW4MTZnZGxm38qx6TqLJCeHEnKW7NhujN6VL7mFbZt6MZ1UcJS/YUYKLnFw1PBbvcOYjTarf2fCtIsCrHKCcYaSaK33L9HrcqoDH/ykOCd57TcNggrFCiqV4sOdjXgFj8Bi7fJbK0QCbIKv03YxBAUiUHArnTP6ANpRiAIyzQxGjGTFjgd2ENgU7Luf346xHdblbwecvJvabmN63mf9a/WFZ21JLERLH2PtAlcbmK43trIjnvHwGeSbi7Pd0xpiXXlhyG+iIdLqbszKjGvYd2cdK4nSfjJhhslA8KS8q5DVp0kJLZKfTbtAVI3mrmVyRAH0ZAa7SXqZQlcQ=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
		{
			title: "unknown algorithm",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-256=n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",algorithm="ed25519",headers="(request-target) date host digest",signature="jFpHNN2jW4MTZnZGxm38qx6TqLJCeHEnKW7NhujN6VL7mFbZt6MZ1UcJS/YUYKLnFw1PBbvcOYjTarf2fCtIsCrHKCcYaSaK33L9HrcqoDH/ykOCd57TcNggrFCiqV4sOdjXgFj8Bi7fJbK0QCbIKv03YxBAUiUHArnTP6ANpRiAIyzQxGjGTFjgd2ENgU7Luf346xHdblbwecvJvabmN63mf9a/WFZ21JLERLH2PtAlcbmK43trIjnvHwGeSbi7Pd0xpiXXlhyG+iIdLqbszKjGvYd2cdK4nSfjJhhslA8KS8q5DVp0kJLZKfTbtAVI3mrmVyRAH0ZAa7SXqZQlcQ=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
		{
			title: "digest does not contain an algorithm",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",algorithm="rsa-sha256",headers="(request-target) date host digest",signature="jFpHNN2jW4MTZnZGxm38qx6TqLJCeHEnKW7NhujN6VL7mFbZt6MZ1UcJS/YUYKLnFw1PBbvcOYjTarf2fCtIsCrHKCcYaSaK33L9HrcqoDH/ykOCd57TcNggrFCiqV4sOdjXgFj8Bi7fJbK0QCbIKv03YxBAUiUHArnTP6ANpRiAIyzQxGjGTFjgd2ENgU7Luf346xHdblbwecvJvabmN63mf9a/WFZ21JLERLH2PtAlcbmK43trIjnvHwGeSbi7Pd0xpiXXlhyG+iIdLqbszKjGvYd2cdK4nSfjJhhslA8KS8q5DVp0kJLZKfTbtAVI3mrmVyRAH0ZAa7SXqZQlcQ=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
		{
			title: "unsupported digest algorithm",
			req: &http.Request{
				Method: "POST",
				URL: &url.URL{
					Path: "/example",
				},
				Header: http.Header{
					"Date":   {"Fri, 29 Jul 2022 13:23:35 GMT"},
					"Host":   {"example.org"},
					"Digest": {"SHA-1=n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg="},
				},
				Body: io.NopCloser(bytes.NewBuffer([]byte("test"))),
			},
			signature: `keyId="abc",algorithm="rsa-sha256",headers="(request-target) date host digest",signature="jFpHNN2jW4MTZnZGxm38qx6TqLJCeHEnKW7NhujN6VL7mFbZt6MZ1UcJS/YUYKLnFw1PBbvcOYjTarf2fCtIsCrHKCcYaSaK33L9HrcqoDH/ykOCd57TcNggrFCiqV4sOdjXgFj8Bi7fJbK0QCbIKv03YxBAUiUHArnTP6ANpRiAIyzQxGjGTFjgd2ENgU7Luf346xHdblbwecvJvabmN63mf9a/WFZ21JLERLH2PtAlcbmK43trIjnvHwGeSbi7Pd0xpiXXlhyG+iIdLqbszKjGvYd2cdK4nSfjJhhslA8KS8q5DVp0kJLZKfTbtAVI3mrmVyRAH0ZAa7SXqZQlcQ=="`,
			requiredHeaders: []string{
				"(request-target)",
				"date",
				"host",
				"digest",
			},
			keyIDMetadataFn: getRSAPublicKey(0, nil),
			errorExpected:   true,
		},
	}

	for _, tc := range testCases {
		// run test case with Authorization header
		tc.req.Header.Set(string(Authorization), "Signature "+tc.signature)
		t.Run(tc.title, tc.test)

		// run test case with Signature header
		tc.req.Header.Del(string(Authorization))
		tc.req.Header.Set(string(Signature), tc.signature)
		t.Run(tc.title, tc.test)
	}
}

type extractSignatureTestCase struct {
	title                    string
	headers                  http.Header
	expectedKeyID            string
	expectedAlgorithm        string
	expectedSignatureHeaders []string
	expectedSignature        string
	errorExpected            bool
}

func (tc *extractSignatureTestCase) test(t *testing.T) {
	ma := &messageAttributes{
		req: &http.Request{
			Header: tc.headers,
		},
	}

	err := ma.extractSignature()

	if tc.errorExpected {
		assert.Error(t, err)
		return
	}

	assert.NoError(t, err)
	assert.Equal(t, tc.expectedKeyID, ma.keyID)
	assert.Equal(t, tc.expectedAlgorithm, ma.algorithm)
	assert.Equal(t, tc.expectedSignatureHeaders, ma.signatureHeaders)
	assert.Equal(t, tc.expectedSignature, ma.signature)
}

func Test_extractSignature(t *testing.T) {
	testCases := []extractSignatureTestCase{
		{
			title: "Authorization header signature extracted",
			headers: http.Header{
				"Authorization": {`Signature keyId="id",algorithm="algo",headers="a b c",signature="sig"`},
			},
			expectedKeyID:            "id",
			expectedAlgorithm:        "algo",
			expectedSignatureHeaders: []string{"a", "b", "c"},
			expectedSignature:        "sig",
			errorExpected:            false,
		},
		{
			title: "Signature header signature extracted",
			headers: http.Header{
				"Signature": {`keyId="id",algorithm="algo",headers="a b c",signature="sig"`},
			},
			expectedKeyID:            "id",
			expectedAlgorithm:        "algo",
			expectedSignatureHeaders: []string{"a", "b", "c"},
			expectedSignature:        "sig",
			errorExpected:            false,
		},
		{
			title: "Authorization header signature extracted with attributes in different order",
			headers: http.Header{
				"Authorization": {`Signature signature="sig",keyId="id",headers="a b c",algorithm="algo"`},
			},
			expectedKeyID:            "id",
			expectedAlgorithm:        "algo",
			expectedSignatureHeaders: []string{"a", "b", "c"},
			expectedSignature:        "sig",
			errorExpected:            false,
		},
		{
			title: "Authorization header no space between type and start of value",
			headers: http.Header{
				"Authorization": {`Signaturesignature="sig",keyId="id",headers="a b c",algorithm="algo"`},
			},
			errorExpected: true,
		},
		{
			title: "Signature header signature extracted with attributes in different order",
			headers: http.Header{
				"Signature": {`signature="sig",keyId="id",headers="a b c",algorithm="algo"`},
			},
			expectedKeyID:            "id",
			expectedAlgorithm:        "algo",
			expectedSignatureHeaders: []string{"a", "b", "c"},
			expectedSignature:        "sig",
			errorExpected:            false,
		},
		{
			title: "Authorization header fails when wrong type",
			headers: http.Header{
				"Authorization": {`Bearer keyId="id",algorithm="algo",headers="a b c",signature="sig"`},
			},
			errorExpected: true,
		},
		{
			title: "Authorization header malformed signature with correct attributes fails",
			headers: http.Header{
				"Authorization": {`Signature signature="sig"keyId="id"headers="a b c"algorithm="algo"`},
			},
			errorExpected: true,
		},
		{
			title: "Signature header malformed signature with correct attributes fails",
			headers: http.Header{
				"Signature": {`signature="sig"keyId="id"headers="a b c"algorithm="algo"`},
			},
			errorExpected: true,
		},
		{
			title: "Authorization and Signature headers error with signature",
			headers: http.Header{
				"Authorization": {`Signature keyId="id",algorithm="algo",headers="a b c",signature="sig"`},
				"Signature":     {`keyId="id",algorithm="algo",headers="a b c",signature="sig"`},
			},
			errorExpected: true,
		},
		{
			title: "Authorization header signature extracted when Signature header doesn't have a signature",
			headers: http.Header{
				"Authorization": {`Signature keyId="id",algorithm="algo",headers="a b c",signature="sig"`},
				"Signature":     {`something else`},
			},
			expectedKeyID:            "id",
			expectedAlgorithm:        "algo",
			expectedSignatureHeaders: []string{"a", "b", "c"},
			expectedSignature:        "sig",
			errorExpected:            false,
		},
		{
			title: "Signature header signature extracted when Authorization header doesn't have a signature",
			headers: http.Header{
				"Authorization": {`something else`},
				"Signature":     {`keyId="id",algorithm="algo",headers="a b c",signature="sig"`},
			},
			expectedKeyID:            "id",
			expectedAlgorithm:        "algo",
			expectedSignatureHeaders: []string{"a", "b", "c"},
			expectedSignature:        "sig",
			errorExpected:            false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, tc.test)
	}
}

func getRSAPublicKey(algo crypto.Hash, err error) KeyIDMetadata {
	return func(keyID string) (crypto.PublicKey, crypto.Hash, error) {
		keyBytes, _ := os.ReadFile("./test-certificates/rsa.pub")
		decoded, _ := pem.Decode(keyBytes)
		pk, _ := x509.ParsePKIXPublicKey(decoded.Bytes)
		return pk, algo, err
	}
}
