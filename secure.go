package secure

import (
    "crypto/rand"
	"crypto/sha512"
	"golang.org/x/crypto/bcrypt"
	"io"
	"io/ioutil"
)

/*
 *
 *
 */
type SecureData struct {
    Ciphered string `json:"ciphered"`
    Salt     string `json:"salt"`
}

func randomString(length int) string {
	b := make([]byte, length)

	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	return string(b)
}

func CreateData(username, password , localsalt string) SecureData, error {
	newsecure := SecureData{Username: username, Salt: randomString(128)}

	h := sha512.New()
	io.WriteString(h, password + localsalt)

	ciphered, err := bcrypt.GenerateFromPassword(append(h.Sum(nil), []byte(newsecure.Salt)...), 10)
	if err != nil {
        return nil, err
    }

	newsecure.Ciphered = string(ciphered)

	return newsecure
}
