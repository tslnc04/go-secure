package secure

import (
        "bytes"
        "golang.org/x/crypto/openpgp"
        "golang.org/x/crypto/openpgp/armor"
        "fmt"
        "io/ioutil"
        "errors"
)

func Encrypt(text string, pass string) string {
        password := []byte(pass)

        encBuf   := bytes.NewBuffer(nil)
        w, err   := armor.Encode(encBuf, "PGP SIGNATURE", nil)
        if err != nil {panic(err)}

        pt, err  := openpgp.SymmetricallyEncrypt(w, password, nil, nil)
        if err != nil {panic(err)}

        message  := []byte(text)
        _, err    = pt.Write(message)

        pt.Close()
        w.Close()

        return encBuf.String()
}

func Decrypt(coded string, pass string) string {
        password    := []byte(pass)

        decBuf      := bytes.NewBufferString(coded)
        result, err := armor.Decode(decBuf)
        if err != nil {panic(err)}

        prompted    := false
        md, err     := openpgp.ReadMessage(result.Body, nil, func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
                if prompted {
                        return nil, errors.New("Couldn't Decrypt Data with Password")
                } else {
                        prompted = true
                }
                return password, nil
        }, nil)
        if err != nil {panic(err)}

        dec, err    := ioutil.ReadAll(md.UnverifiedBody)
        if err != nil {panic(err)}

        return string(dec)
}
