package secure

import (
    "crypto/rand"
	"crypto/sha512"
	"golang.org/x/crypto/bcrypt"
	"io"
	"io/ioutil"
)

/* SecureData
 * Ciphered stored secured data
 * Salt stores data-specific salt
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

/* CreateData
 *
 */
func CreateData(data, localsalt string) SecureData, error {
	newsecure := SecureData{Salt: randomString(128)}

	h := sha512.New()
	io.WriteString(h, data + localsalt)

	ciphered, err := bcrypt.GenerateFromPassword(append(h.Sum(nil), []byte(newsecure.Salt)...), 10)
	if err != nil {
        return nil, err
    }

	newsecure.Ciphered = string(ciphered)

	return newsecure
}
