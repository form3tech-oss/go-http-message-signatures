# Go HTTP Message Signatures

Go implementation of the [draft HTTP Message Signatures RFC](https://www.ietf.org/archive/id/draft-cavage-http-signatures-12.txt). 

**Please note the version of the draft this is based on as there are varying versions which are incompatible.**

## Usage

```go
import "github.com/form3tech-oss/go-http-message-signatures"
```

### Signing

A `MessageSigner` requires a `Signer` implementation to sign any messages. This library currently provides an `RSA` signer, or you can provide your own or contribute new signers back to this library.

```go
keyBytes, err := os.ReadFile("path/to/private.key")
if err != nil {
    ...
}

decoded, err := pem.Decode(keyBytes)
if err != nil {
    ...
}

privateKey, err := x509.ParsePKCS1PrivateKey(decoded.Bytes)
if err != nil {
    ...
}

signer, err := NewRSASigner(privateKey, crypto.SHA256)
if err != nil {
    ...
}
```

Once you have a `Signer`, you can use it in a `MessageSigner` to sign a request. If the request contains a non-empty `body`, then a `Digest` header will be generated with the given algorithm. This will only be used in the signature if provided in the list of headers to sign. You can also choose which header to populate the signature on, either `Authorization` or `Signature`.

```go
digestAlgorithm := crypto.SHA256
keyID := "id-that-maps-to-public-key-on-server"
messageSigner, err := NewMessageSigner(digestAlgorithm, signer, keyID, httpsignatures.Authorization)
if err != nil {
    ...
}

signatureHeaders := []string{httpsignature.RequestTarget, "date", "host", "digest"}

req := createHTTPRequest()
req, err = messageSigner.SignRequest(req, signatureHeaders)
if err != nil {
    ...
}
```

### Verifying

A `MessageVerifier` can be given a list of headers that are required in the message signature and a function that provides a public key and an optional expected hashing algorithm for a given `keyId`.

```go
func keyIDFetcher(keyID string) (crypto.PublicKey, crypto.Hash, error) {
    keyBytes, err := os.ReadFile("path/to/public.key")
    if err != nil {
        ...
    }

    decoded, err := pem.Decode(keyBytes)
    if err != nil {
        ...
    }

    publicKey, err := x509.ParsePKIXPublicKey(decoded.Bytes)
    if err != nil {
        ...
    }

    rsaPK, ok := publicKey.(*rsa.PublicKey)
    if !ok {
        ...
    }
    return rsaPK, 0, nil
}

verifier := NewMessageVerifier(nil, keyIDFetcher)
```

Once you have a `MessageVerifier`, you can use it to verify an HTTP request. If the signature on the request contains the `digest` header, then the digest will be validated against the request `body`. If any `requiredHeaders` were provided, the signature headers will be validated against these. The `keyId` is then extracted and the signature is verified using the public key and optional hashing algorithm returned by the function provided to `MessageVerifier`.

```go
err := verifier.VerifyRequest(req)
if err != nil {
    ...
}
```