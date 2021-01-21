package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"golang.org/x/crypto/bcrypt"
)

var db *gorm.DB

func init() {
	//open a db connection
	var err error
	db, err = gorm.Open("mysql", "root:toor@/test_majoo?charset=utf8&parseTime=True&loc=Local")
	if err != nil {
		panic("failed to connect database")
	}

	//Migrate the schema
	db.AutoMigrate(&User{})
}

func main() {
	router := gin.Default()

	router.POST("/login", Login)

	router.Static("/photos", "./photos")

	v1 := router.Group("/api/v1/users", TokenAuthMiddleware())
	{
		v1.GET("/", getAllUser)
		v1.GET("/:id", getUser)
		v1.POST("/", createUser)
		v1.PUT("/:id", updateUser)
		v1.DELETE("/:id", deleteUser)
	}
	router.Run()
}

type (
	// User describes a User type
	User struct {
		gorm.Model
		Username string `gorm:"not null" json:"username"`
		Password string `gorm:"not null" json:"password"`
		FullName string `gorm:"not null" json:"full_name"`
		Photo    string `json:"photo"`
	}

	// resourceUser represents a formatted user
	resourceUser struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
		FullName string `json:"full_name"`
		Photo    string `json:"photo"`
	}
)

func Login(c *gin.Context) {
	var user User

	db.Where("username = ?", c.PostForm("username")).First(&user)

	password := []byte(c.PostForm("password"))

	log.Println(c.PostForm("username"))
	log.Println(password)

	isMatch := comparePasswords(user.Password, password)

	log.Println(user.Username)
	log.Println(user.Password)

	//compare the user from the request, with the one we defined:
	if !isMatch || user.ID == 0 {
		c.JSON(http.StatusUnauthorized, "Please provide valid login details")
		return
	}
	token, err := CreateToken(user.ID)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	c.JSON(http.StatusOK, token)
}

func CreateToken(userId uint) (string, error) {
	var err error
	//Creating Access Token
	os.Setenv("ACCESS_SECRET", "majoo") //this should be in an env file
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = userId
	atClaims["exp"] = time.Now().Add(time.Minute * 60).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, err := at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return "", err
	}
	return token, nil
}

func comparePasswords(hashedPwd string, plainPwd []byte) bool {
	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}

func ExtractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	//normally Authorization the_token_xxx
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := ExtractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func TokenValid(r *http.Request) error {
	token, err := VerifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}

func TokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := TokenValid(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, err.Error())
			c.Abort()
			return
		}
		c.Next()
	}
}

func getAllUser(c *gin.Context) {
	var users []User
	var _users []resourceUser

	db.Find(&users)

	if len(users) <= 0 {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "No user found!"})
		return
	}

	//transforms the users for building a good response
	for _, item := range users {
		_users = append(_users, resourceUser{
			ID:       item.ID,
			Username: item.Username,
			FullName: item.FullName,
			Photo:    item.Photo,
		})
	}

	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "data": _users})
}

func getUser(c *gin.Context) {
	var user User
	userID := c.Param("id")

	db.First(&user, userID)

	if user.ID == 0 {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "No user found!"})
		return
	}

	_user := resourceUser{
		ID:       user.ID,
		Username: user.Username,
		FullName: user.FullName,
		Photo:    user.Photo,
	}

	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "data": _user})
}

func createUser(c *gin.Context) {
	password := []byte(c.PostForm("password"))

	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)

	photo, err := c.FormFile("photo")

	if err != nil {
		panic(err)
	}

	path := "photos/" + photo.Filename

	if err := c.SaveUploadedFile(photo, path); err != nil {
		panic(err)
	}

	user := User{
		Username: c.PostForm("username"),
		Password: string(hashedPassword),
		FullName: c.PostForm("full_name"),
		Photo:    path,
	}

	db.Save(&user)

	c.JSON(http.StatusCreated, gin.H{"status": http.StatusCreated, "message": "User item created successfully!", "resourceId": user.ID})
}

func updateUser(c *gin.Context) {
	var user User

	userID := c.Param("id")

	db.First(&user, userID)

	if user.ID == 0 {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "No user found!"})
		return
	}

	rawPassword := []byte(c.PostForm("password"))

	hashedPassword, err := bcrypt.GenerateFromPassword(rawPassword, bcrypt.DefaultCost)

	if err != nil {
		panic(err)
	}

	db.Model(&user).Update(User{
		Username: c.PostForm("username"),
		Password: string(hashedPassword),
		FullName: c.PostForm("full_name"),
		Photo:    c.PostForm("photo"),
	})

	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "User updated successfully!"})
}

func deleteUser(c *gin.Context) {
	var user User

	userID := c.Param("id")

	db.First(&user, userID)

	if user.ID == 0 {
		c.JSON(http.StatusNotFound, gin.H{"status": http.StatusNotFound, "message": "No user found!"})
		return
	}

	db.Delete(&user)

	c.JSON(http.StatusOK, gin.H{"status": http.StatusOK, "message": "User deleted successfully!"})
}
