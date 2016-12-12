# jwt
[![Build Status](https://travis-ci.org/DavidCai1993/jwt.svg?branch=master)](https://travis-ci.org/DavidCai1993/jwt)
[![Coverage Status](https://coveralls.io/repos/github/DavidCai1993/jwt/badge.svg?branch=master)](https://coveralls.io/github/DavidCai1993/jwt?branch=master)

 [Json Web Token](https://jwt.io/introduction/) implementation for Go. Inspired by https://github.com/auth0/node-jsonwebtoken .

## Installation

```
go get -u github.com/DavidCai1993/jwt
```

## Documentation

API documentation can be found here: https://godoc.org/github.com/DavidCai1993/jwt

## Usage

### Sign:

```go
payload := map[string]interface{}{"foo": "bar"}

// Sign with default (HMAC SHA256)
token, err = jwt.Sign(payload, "secret", nil)

// Sign a jwt which ttl is 10s
token, err = jwt.Sign(payload, "secret", &jwt.SignOption{
  ExpiresIn: 10 * time.Second,
})

privateKey, _ := rsa.GenerateKey(rand.Reader, 1024)

// Sign with RSA SHA256
token, err = jwt.Sign(payload, privateKey, &jwt.SignOption{
  Algorithm: jwt.RS256,
})
```

### Verify:

```go
// Verify a token symmetric
header, payload, err = jwt.Verify(token, "secret", nil)

// Verify audience
header, payload, err = jwt.Verify(token, "secret", &jwt.VerifyOption{
  Audience: "fooAud",
})

// Verify issuer
header, payload, err = jwt.Verify(token, "secret", &jwt.VerifyOption{
  Issuer: "fooIss",
})

// Verify subject and expiration
header, payload, err = jwt.Verify(token, "secret", &jwt.VerifyOption{
  Subject:        "fooSub",
  ClockTolerance: 15 * time.Second,
})
```
