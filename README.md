secure
============

secure encrypts and decrypts data, as well as obtaining key based on the password (using PBKDF2).

## Example

```go
package main

import (
	"fmt"

	"github.com/AntonMezhanskiy/secure"
)

func main() {
	var plaintext = []byte("Привет, Мир!")
	var pass = []byte("password")
	var salt = []byte("salt")
	var key = secure.GenerateKey(pass, salt)

	a, _ := secure.EncryptData(plaintext, key)
	b, _ := secure.DecryptData(a, key)
	fmt.Println(string(b))
}
```