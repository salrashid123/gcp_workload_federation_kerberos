package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/net/http2"
	goidentity "gopkg.in/jcmturner/goidentity.v3"
	"gopkg.in/jcmturner/gokrb5.v7/keytab"
	"gopkg.in/jcmturner/gokrb5.v7/service"
	"gopkg.in/jcmturner/gokrb5.v7/spnego"
)

const (
	AccessToken string = "urn:ietf:params:oauth:token-type:access_token"
)

var (
	cacert     = flag.String("cacert", "certs/root-ca.crt", "RootCA")
	servercert = flag.String("servercert", "certs/linux.crt", "Server Cert")
	serverkey  = flag.String("serverkey", "certs/linux.key", "Server Key")
	port       = flag.String("port", ":9080", "Listener port")
	keytabFile = flag.String("keytabFile", "http.keytab", "KeyTab")
	jwtKey     = flag.String("jwtKey", "certs/jwt.key", "Signing Cert")
	jwtPublic  = flag.String("jwtPublic", "certs/jwt.crt", "Signing Cert")

	staticToken = flag.String("staticToken", "some_access_token", "test access_token")

	priv   *rsa.PrivateKey
	pubKey *rsa.PublicKey
)

type contextKey string

const contextEventKey contextKey = "event"

type event struct {
	ekm string
}

type cClaims struct {
	jwt.RegisteredClaims

	Domain    string           `json:"domain"`
	SessionID string           `json:"session_id"`
	AuthTime  *jwt.NumericDate `json:"auth_time"`
}

func eventsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		event := &event{
			ekm: "",
		}
		ctx := context.WithValue(r.Context(), contextEventKey, *event)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}
func main() {

	flag.Parse()

	l := log.New(os.Stderr, "GOKRB5 Service: ", log.Ldate|log.Ltime|log.Lshortfile)

	kt, err := keytab.Load(*keytabFile)
	if err != nil {
		log.Fatalf("Error loading keytab: %v", err)
	}

	spriv, err := os.ReadFile(*jwtKey)
	if err != nil {
		log.Fatalf("Error loading jwt signing key: %v", err)
	}

	priv, err = parseRSAPrivateKeyFromPEM(spriv)
	if err != nil {
		log.Fatalf("Error loading jwt signing public: %v", err)
	}

	spub, _ := os.ReadFile(*jwtPublic)
	if err != nil {
		log.Fatalf("Error loading jwt signing public: %v", err)
	}

	pubKey, err = parseRSAPublicKeyFromPEM(spub)
	if err != nil {
		log.Fatalf("Error loading jwt signing public: %v", err)
	}

	th := http.HandlerFunc(authenticateHandler)

	mux := http.NewServeMux()
	mux.Handle("/authenticate", spnego.SPNEGOKRB5Authenticate(th, kt, service.Logger(l)))
	mux.Handle("/v1/token", http.HandlerFunc(tokenHandler))

	tlsConfig := &tls.Config{}

	server := &http.Server{
		Addr:      *port,
		Handler:   eventsMiddleware(mux),
		TLSConfig: tlsConfig,
	}
	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	log.Fatal(server.ListenAndServeTLS(*servercert, *serverkey))

}

type execResponseError struct {
	Version int    `json:"version"`
	Success bool   `json:"success"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type execResponse struct {
	Version        int              `json:"version"`
	Success        bool             `json:"success"`
	TokenType      string           `json:"token_type"`
	IdToken        string           `json:"id_token"`
	ExpirationTime *jwt.NumericDate `json:"expiration_time"`
}

type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type,omitempty"`
	ExpiresIn       int64  `json:"expires_in,omitempty"`
	Scope           string `json:"scope,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing form %v", err)
		http.Error(w, "{\"error\":\"invalid_request\",\"error_description\":\"error parsing form\"}", http.StatusBadRequest)
		return
	}

	tok := r.FormValue("subject_token")
	aud := r.FormValue("audience")
	//log.Printf("subject_token: %s\n", tok)
	log.Printf("audience: %s\n", aud)

	// tok, err := io.ReadAll(r.Body)
	// if err != nil {
	// 	http.Error(w, fmt.Sprintf("Error reading body: %v", err), http.StatusInternalServerError)
	// 	return
	// }

	keyfunc := func(token *jwt.Token) (interface{}, error) {
		return pubKey, nil
	}

	vtoken, err := jwt.Parse(tok, keyfunc, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("https://my_kdc_server"), jwt.WithAudience("https://my_sts_exchange_server"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error verifying token %v", err)
		http.Error(w, "{\"error\":\"invalid_request\",\"error_description\":\"error verifying token\"}", http.StatusBadRequest)
		return

	}
	if !vtoken.Valid {
		fmt.Fprintf(os.Stderr, "error token not valid subject")
		http.Error(w, "{\"error\":\"invalid_request\",\"error_description\":\"Invalid token\"}", http.StatusBadRequest)
		return
	}

	// >>> important, extract the subject or other claims and figure out if the user should get an access_token

	sub, err := vtoken.Claims.GetSubject()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error getting subject %v", err)
		http.Error(w, "{\"error\":\"invalid_request\",\"error_description\":\"Internal error getting subject\"}", http.StatusBadRequest)
		return
	}

	// for now i'm just setting a static one
	if sub == "client1" {
		w.WriteHeader(http.StatusOK)
		p := &TokenResponse{
			AccessToken:     *staticToken,
			IssuedTokenType: AccessToken,
			TokenType:       "Bearer",
			ExpiresIn:       int64(3600),
		}
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache, no-store")

		err = json.NewEncoder(w).Encode(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not marshall JSON to output %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		return
	}
	// otherwise unauthorized
	w.Header().Set("Content-Type", "application/json")
	http.Error(w, "{\"error\":\"invalid_request\",\"error_description\":\"Subject unauthorized\"}", http.StatusBadRequest)
}

func sendError(w http.ResponseWriter, r *http.Request, code int, message string) {
	vr := &execResponseError{
		Version: 1,
		Success: false,
		Code:    code,
		Message: message,
	}

	jsonResponse, err := json.Marshal(vr)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error encoding error JWT %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(jsonResponse)
}

func authenticateHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	creds := ctx.Value(spnego.CTXKeyCredentials).(goidentity.Identity)

	if creds == nil {
		sendError(w, r, http.StatusForbidden, "error processing SPNEGO credentials")
		return
	}

	cclaims := cClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  &jwt.NumericDate{time.Now()},
			ExpiresAt: &jwt.NumericDate{time.Now().Add(time.Second * 1)},
			Issuer:    "https://my_kdc_server",
			Audience:  jwt.ClaimStrings([]string{"https://my_sts_exchange_server"}),
			Subject:   creds.UserName(),
		},
		Domain:    creds.Domain(),
		SessionID: creds.SessionID(),
		AuthTime:  &jwt.NumericDate{creds.AuthTime()},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, cclaims)

	out, err := token.SignedString(priv)
	if err != nil {
		log.Printf("Error creating JWT %v", err)
		sendError(w, r, http.StatusInternalServerError, fmt.Sprintf("error processing creating JWT %v", err))
		return
	}

	vr := &execResponse{
		Version:        1,
		Success:        true,
		TokenType:      "urn:ietf:params:oauth:token-type:id_token",
		IdToken:        out,
		ExpirationTime: &jwt.NumericDate{time.Now().Add(time.Second * 20)},
	}

	jsonResponse, err := json.Marshal(vr)
	if err != nil {
		sendError(w, r, http.StatusInternalServerError, fmt.Sprintf("Error marshalling Response JWT %v", err))
		return

	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonResponse)

}

func parseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New("invalid Key: Key must be a PEM encoded PKCS1 or PKCS8 key")
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	var pkey *rsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, errors.New("key is not a valid RSA public key")
	}

	return pkey, nil
}

// Parse PEM encoded PKCS1 or PKCS8 private key
func parseRSAPrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errors.New("invalid Key: Key must be a PEM encoded PKCS1 or PKCS8 key")
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var pkey *rsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, errors.New("key is not a valid RSA private key")
	}

	return pkey, nil
}
