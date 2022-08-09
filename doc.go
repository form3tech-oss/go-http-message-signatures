// Package httpsignatures provides tools to sign HTTP requests as per https://www.ietf.org/archive/id/draft-cavage-http-signatures-12.txt

// Please note the version of the draft this is based on as there are varying versions which are incompatible.

// Example usage

// The following is an example using an RSA private key for signing. Note: check(err) has been used as a shorthand for error handling.

//    import (
//    	  "net/http"

// 		  httpsignatures "github.com/form3tech-oss/go-http-message-signatures"
// 	  )

//    keyBytes, err := os.ReadFile("./test-certificates/rsa.pem")
//    check(err)

//    decodedKey, err := pem.Decode(keyBytes)
//    check(err)

//    privateKey, err := x509.ParsePKCS1PrivateKey(decodedKey.Bytes)
//    check(err)

//    rsaSigner, err := httpsignatures.NewRSASigner(privateKey, crypto.SHA256)
//    check(err)

//    publicKeyID := "ID on receiving server that maps to RSA public key"
//    messageSigner, err := httpsignatures.NewMessageSigner(
//	      crypto.SHA256,
//		  rsaSigner,
//		  publicKeyID,
//		  httpsignatures.Authorization
//	  )
//    check(err)

//    req := ... // create a request

//    headersToSign := []string{"(request-target)"} // add any immutable headers in request, include digest if your request has a body

//    signedReq, err := messageSigner.SignMessage(req, headersToSign)
//    check(err)

//    resp, err := http.DefaultClient.Do(signedReq)
//    check(err)
package httpsignatures
