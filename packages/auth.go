package backend

import (
	"encoding/json"
	"errors"
	"net/http"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
)

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// declaring variable outside function
var GetToken map[string]interface{}

func Middleware() (*jwtmiddleware.JWTMiddleware, map[string]interface{}) {
	// jwtMiddleware is a handler that will verify access tokens
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			// get token for database
			// assigning value to earlier declared variable through pointer
			p := &GetToken
			*p = token.Claims.(jwt.MapClaims)

			// Verify 'aud' claim
			// 'aud' = audience (where you deploy the backend, either locally or Heroku)
			aud := "YOUR_API_IDENTIFIER" // CHANGE THIS LATER

			// convert audience in the JWT token to []interface{} if multiple audiences
			convAud, ok := token.Claims.(jwt.MapClaims)["aud"].([]interface{})
			if !ok {
				// convert audience in the JWT token to string if only 1 audience
				strAud, ok := token.Claims.(jwt.MapClaims)["aud"].(string)
				// return error if can't convert to string
				if !ok {
					return token, errors.New("invalid audience")
				}
				// return error if audience doesn't match
				if strAud != aud {
					return token, errors.New("invalid audience")
				}
			} else {
				for _, v := range convAud {
					// verify if audience in JWT is the one you've set
					if v == aud {
						break
					} else {
						return token, errors.New("invalid audience")
					}
				}
			}

			// Verify 'iss' claim
			// 'iss' = issuer
			iss := "https://YOUR_DOMAIN/"
			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
			if !checkIss {
				return token, errors.New("invalid issuer")
			}

			cert, err := getPermCert(token)
			if err != nil {
				panic(err.Error())
			}

			result, _ := jwt.ParseRSAPrivateKeyFromPEM([]byte(cert))
			return result, nil
		},
		SigningMethod: jwt.SigningMethodRS256,
	})
	return jwtMiddleware, GetToken
}

// function to grab JSON Web Key Set and return the certificate with the public key
func getPermCert(token *jwt.Token) (string, error) {
	cert := ""
	resp, err := http.Get("https://YOUR_DOMAIN/.well-known.jwks.json")

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("unable to find appropriate key")
		return cert, err
	}

	return cert, nil
}
