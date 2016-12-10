package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

func decode(token string) (dh map[string]interface{}, dp map[string]interface{}, err error) {
	splited := strings.Split(token, ".")

	if len(splited) != 3 {
		return nil, nil, ErrInvalidToken
	}

	h, err := base64.StdEncoding.DecodeString(splited[0])

	if err != nil {
		return nil, nil, err
	}

	if err := json.Unmarshal(h, dh); err != nil {
		return nil, nil, err
	}

	p, err := base64.StdEncoding.DecodeString(splited[1])

	if err != nil {
		return nil, nil, err
	}

	if err := json.Unmarshal(p, dp); err != nil {
		return nil, nil, err
	}

	return dh, dp, nil
}
