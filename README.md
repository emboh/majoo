# majoo
 
## Majoo Test Case

How to up & running:

Install dependecies.
- go get github.com/dgrijalva/jwt-go
- go get github.com/gin-gonic/gin
- go get github.com/jinzhu/gorm
- go get github.com/jinzhu/gorm/dialects/mysql
- go get golang.org/x/crypto/bcrypt

Create database "test_majoo"

Run command for initialize.
- go run main.go

Create initial User in database for testing purpose, fill the username, password (bcrypt hashed), full_name field in users table.

Done.
