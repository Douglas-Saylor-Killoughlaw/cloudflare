// Copyright 2018 Cloudflare <sevki@cloudflare.com>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cloudflare // import "github.com/jennyservices/cloudflare"

import (
	"context"
	"crypto"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	stdjwt "github.com/dgrijalva/jwt-go"
	kitjwt "github.com/go-kit/kit/auth/jwt"
	"github.com/jennyservices/jenny/auth"
	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"
	"sevki.org/x/pretty"
)

func ReqJWTExtractor(ctx context.Context, req *http.Request) context.Context {
	accessJWT := req.Header.Get("Cf-Access-Jwt-Assertion")
	if accessJWT == "" {
		return ctx
	}
	return context.WithValue(ctx, kitjwt.JWTTokenContextKey, accessJWT)
}

func KeyFunc(tok *stdjwt.Token) (interface{}, error) {
	claims := tok.Claims.(*Claims)
	certsURL := fmt.Sprintf("%s/cdn-cgi/access/certs", claims.Issuer)

	req, err := http.Get(certsURL)
	if err != nil {
		return nil, errors.Wrap(err, "keyfunc")
	}

	keys := new(jose.JSONWebKeySet)
	dec := json.NewDecoder(req.Body)
	if err := dec.Decode(keys); err != nil {
		return nil, errors.Wrap(err, "keyfunc: jsondecode")
	}
	kid, ok := tok.Header["kid"].(string)
	if !ok {
		return nil, errors.New("jwt doesn't have kid")
	}
	macthing := keys.Key(kid)
	if len(macthing) > 0 {
		return macthing[0].Key, nil
	}
	if tok == nil {
		return nil, errors.New("no token present")
	}

	return nil, errors.New("no kid present")
}

func ClaimsFactory() stdjwt.Claims {
	return &Claims{}
}

var SigningMethod = &stdjwt.SigningMethodRSA{
	Name: "RS256",
	Hash: crypto.SHA256,
}

func UserExcractor(claims stdjwt.Claims) (auth.User, error) {
	log.Println(pretty.JSON(claims))
	return &AccessUser{claims.(*Claims)}, nil
}

type Claims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience audience `json:"aud"`
	Expiry   jsonTime `json:"exp"`
	IssuedAt jsonTime `json:"iat"`
	Nonce    string   `json:"nonce"`
	Email    string   `json:"email"`
}

func (c *Claims) Valid() error {
	return nil
}

type AccessUser struct {
	*Claims
}

func (a *AccessUser) UniqueID() []byte {
	h := sha512.New()
	io.WriteString(h, a.Issuer)
	io.WriteString(h, a.Claims.Email)
	return h.Sum(nil)
}
func (a *AccessUser) Email() string                { return a.Claims.Email }
func (a *AccessUser) DisplayName() (string, error) { return "", nil }
func (a *AccessUser) Details() map[string]string   { return nil }

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {

	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = audience{s}
		return nil
	}
	var auds []string
	if err := json.Unmarshal(b, &auds); err != nil {
		return err
	}
	*a = audience(auds)
	return nil
}

type jsonTime time.Time

func (j *jsonTime) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	var unix int64

	if t, err := n.Int64(); err == nil {
		unix = t
	} else {
		f, err := n.Float64()
		if err != nil {
			return err
		}
		unix = int64(f)
	}
	*j = jsonTime(time.Unix(unix, 0))
	return nil
}
