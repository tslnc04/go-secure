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
    Secured string `json:"ciphered"`
    Salt    string `json:"salt"`
}

func randomString(length int) string {
	b := make([]byte, length)

	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	return string(b)
}

/* CreateDataLocal
 * Creates and uses data-specific salt
 * Also uses local salt given. Should be stored on machine.
 */
func CreateDataLocal(data, localsalt string) SecureData, error {
	newsecure := SecureData{Salt: randomString(128)}

	h := sha512.New()
	io.WriteString(h, data + localsalt)

	ciphered, err := bcrypt.GenerateFromPassword(append(h.Sum(nil), []byte(newsecure.Salt)...), 10)
	if err != nil {
        return nil, err
    }

	newsecure.Secured = string(ciphered)

	return newsecure, nil
}

/* CreateData
 * Creates and uses data-specific salt
 * Doesn't use local salt, but not recommended as it's less secure
 */
func CreateData(data string) SecureData, error {
	newsecure := SecureData{Salt: randomString(128)}

	h := sha512.New()
	io.WriteString(h, data)

	ciphered, err := bcrypt.GenerateFromPassword(append(h.Sum(nil), []byte(newsecure.Salt)...), 10)
	if err != nil {
        return nil, err
    }

	newsecure.Ciphered = string(ciphered)

	return newsecure, nil
}
