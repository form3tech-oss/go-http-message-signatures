# Go HTTP Message Signatures

Go implementation of the [draft HTTP Message Signatures RFC](https://www.ietf.org/archive/id/draft-cavage-http-signatures-12.txt). 

**Please note the version of the draft this is based on as there are varying versions which are incompatible.**

## Usage

`import "github.com/form3tech-oss/go-http-message-signatures"

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
