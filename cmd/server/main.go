package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite"
)

const authorizationCookieName = "authorization"

type User struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"-"`
	Balance  int64  `json:"balance"`
	IsAdmin  bool   `json:"is_admin"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=4,max=20"`
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Phone    string `json:"phone" binding:"required"`
	Password string `json:"password" binding:"required,min=8"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type WithdrawAccountRequest struct {
	Password string `json:"password"`
}

type UserResponse struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Balance  int64  `json:"balance"`
	IsAdmin  bool   `json:"is_admin"`
}

type LoginResponse struct {
	AuthMode string       `json:"auth_mode"`
	Token    string       `json:"token"`
	User     UserResponse `json:"user"`
}

type PostView struct {
	ID          uint   `json:"id"`
	Title       string `json:"title"`
	Content     string `json:"content"`
	OwnerID     uint   `json:"owner_id"`
	Author      string `json:"author"`
	AuthorEmail string `json:"author_email"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type CreatePostRequest struct {
	Title   string `json:"title" binding:"required"`
	Content string `json:"content"`
}

type UpdatePostRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

type PostListResponse struct {
	Posts []PostView `json:"posts"`
}

type PostResponse struct {
	Post PostView `json:"post"`
}

type DepositRequest struct {
	Amount int64 `json:"amount"`
}

type BalanceWithdrawRequest struct {
	Amount int64 `json:"amount"`
}

type TransferRequest struct {
	ToUsername string `json:"to_username"`
	Amount     int64  `json:"amount"`
}

type Store struct {
	db *sql.DB
}

type SessionStore struct {
	tokens map[string]User
}

func main() {
	store, err := openStore("./app.db", "./schema.sql", "./seed.sql")
	if err != nil {
		panic(err)
	}
	defer store.close()

	sessions := newSessionStore()

	router := gin.Default()
	registerStaticRoutes(router)

	auth := router.Group("/api/auth")
	{
		auth.POST("/register", func(c *gin.Context) {
			var request RegisterRequest

			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid register request"})
				return
			}

			query :=
				`
					INSERT INTO users (username, password, name, email, phone) 
					VALUES (?, ?, ?, ?, ?)
				`

			_, err = store.db.Exec(query, request.Username, request.Password, request.Name, request.Email, request.Phone)
			if err != nil {
				c.JSON(http.StatusConflict, gin.H{"message": "username or email already exists"})
				return
			}

			c.JSON(http.StatusCreated, gin.H{
				"message": "register success",
				"user": gin.H{
					"username": request.Username,
					"name":     request.Name,
					"email":    request.Email,
					"phone":    request.Phone,
				},
			})
		})

		auth.POST("/login", func(c *gin.Context) {
			var request LoginRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid login request"})
				return
			}

			user, ok, err := store.findUserByUsername(request.Username)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to load user"})
				return
			}
			if !ok || user.Password != request.Password {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid credentials"})
				return
			}

			token, err := sessions.create(user)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create session"})
				return
			}

			c.SetSameSite(http.SameSiteLaxMode)
			c.SetCookie(authorizationCookieName, token, 60*60*8, "/", "", false, true)
			c.JSON(http.StatusOK, LoginResponse{
				AuthMode: "header-and-cookie",
				Token:    token,
				User:     makeUserResponse(user),
			})
		})

		auth.POST("/logout", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			sessions.delete(token)
			clearAuthorizationCookie(c)
			c.JSON(http.StatusOK, gin.H{
				"message": "logout success",
			})
		})

		auth.POST("/withdraw", func(c *gin.Context) {
			var request WithdrawAccountRequest

			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid withdraw request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}

			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			if user.Password != request.Password {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "wrong password"})
				return
			}

			query :=
				`
					DELETE FROM users 
					WHERE id = ?
				`

			_, err = store.db.Exec(query, user.ID)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "account deletion failed"})
				return
			}

			sessions.delete(token)
			clearAuthorizationCookie(c)

			c.JSON(http.StatusAccepted, gin.H{
				"message": "withdraw success",
			})
		})
	}

	protected := router.Group("/api")
	{
		protected.GET("/me", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}

			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"user": makeUserResponse(user)})
		})

		protected.POST("/banking/deposit", func(c *gin.Context) {
			var request DepositRequest

			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid deposit request"})
				return
			}

			if request.Amount <= 0 {
				c.JSON(http.StatusBadRequest, gin.H{"message": "amount must be greater than zero"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}

			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			query :=
				`
					UPDATE users 
					SET balance = balance + ? 
					WHERE id = ?
				`

			_, err := store.db.Exec(query, request.Amount, user.ID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to update balance"})
				return
			}

			user.Balance += request.Amount
			sessions.tokens[token] = user

			c.JSON(http.StatusOK, gin.H{
				"message": "deposit success",
				"user":    makeUserResponse(user),
				"amount":  request.Amount,
			})
		})

		protected.POST("/banking/withdraw", func(c *gin.Context) {
			var request BalanceWithdrawRequest

			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid withdraw request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}

			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			if request.Amount <= 0 {
				c.JSON(http.StatusBadRequest, gin.H{"message": "amount must be greater than zero"})
				return
			}

			if user.Balance < request.Amount {
				c.JSON(http.StatusBadRequest, gin.H{"message": "insufficient balance"})
				return
			}

			query :=
				`
					UPDATE users 
					SET balance = balance - ? 
					WHERE id = ?
				`

			_, err := store.db.Exec(query, request.Amount, user.ID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to update balance"})
				return
			}

			user.Balance -= request.Amount
			sessions.tokens[token] = user

			c.JSON(http.StatusOK, gin.H{
				"message": "withdraw success",
				"user":    makeUserResponse(user),
				"amount":  request.Amount,
			})
		})

		protected.POST("/banking/transfer", func(c *gin.Context) {
			var request TransferRequest

			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid transfer request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}

			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			if user.Username == request.ToUsername {
				c.JSON(http.StatusBadRequest, gin.H{"message": "cannot transfer to yourself"})
				return
			}

			if request.Amount <= 0 {
				c.JSON(http.StatusBadRequest, gin.H{"message": "amount must be greater than zero"})
				return
			}

			tx, err := store.db.Begin()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to start transaction"})
				return
			}
			defer tx.Rollback()

			query :=
				`
					UPDATE users 
					SET balance = balance - ? 
					WHERE id = ? 
					AND balance >= ?
				`

			res, err := tx.Exec(query, request.Amount, user.ID, request.Amount)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "sender balance update failed"})
				return
			}

			rowsAffected, _ := res.RowsAffected()
			if rowsAffected == 0 {
				c.JSON(http.StatusBadRequest, gin.H{"message": "insufficient balance"})
				return
			}

			query =
				`
					UPDATE users 
					SET balance = balance + ? 
					WHERE username = ?
				`

			res, err = tx.Exec(query, request.Amount, request.ToUsername)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "receiver update failed"})
				return
			}

			rowsAffected, _ = res.RowsAffected()
			if rowsAffected == 0 {
				c.JSON(http.StatusNotFound, gin.H{"message": "receiver not found"})
				return
			}

			if err := tx.Commit(); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to commit transaction"})
				return
			}

			user.Balance -= request.Amount
			sessions.tokens[token] = user

			c.JSON(http.StatusOK, gin.H{
				"message": "transfer success",
				"user":    makeUserResponse(user),
				"to":      request.ToUsername,
				"amount":  request.Amount,
			})
		})

		protected.GET("/posts", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			query :=
				`
					SELECT posts.id, posts.title, posts.content, posts.owner_id, users.name, users.email, posts.created_at, posts.updated_at 
					FROM posts 
					JOIN users 
					ON posts.owner_id = users.id 
					ORDER BY posts.id
				`

			rows, err := store.db.Query(query)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to fetch posts"})
				return
			}

			defer rows.Close()
			var posts []PostView

			for rows.Next() {
				var p PostView
				err := rows.Scan(&p.ID, &p.Title, &p.Content, &p.OwnerID, &p.Author, &p.AuthorEmail, &p.CreatedAt, &p.UpdatedAt)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to scan post"})
					return
				}
				posts = append(posts, p)
			}

			if posts == nil {
				posts = []PostView{}
			}

			c.JSON(http.StatusOK, PostListResponse{
				Posts: posts,
			})
		})

		protected.POST("/posts", func(c *gin.Context) {
			var request CreatePostRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid create request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			query :=
				`
					INSERT INTO posts (title, content, owner_id) 
					VALUES (?, ?, ?)
				`

			_, err = store.db.Exec(query, request.Title, request.Content, user.ID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create post"})
				return
			}

			now := time.Now().Format(time.RFC3339)
			c.JSON(http.StatusCreated, gin.H{
				"message": "post success",
				"post": PostView{
					ID:          1,
					Title:       strings.TrimSpace(request.Title),
					Content:     strings.TrimSpace(request.Content),
					OwnerID:     user.ID,
					Author:      user.Name,
					AuthorEmail: user.Email,
					CreatedAt:   now,
					UpdatedAt:   now,
				},
			})
		})

		protected.GET("/posts/:id", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			query :=
				`
					SELECT posts.id, posts.title, posts.content, posts.owner_id, users.name, users.email, posts.created_at, posts.updated_at 
					FROM posts 
					JOIN users 
					ON posts.owner_id = users.id 
					WHERE posts.id = ?
				`

			var p PostView
			id := c.Param("id")
			err := store.db.QueryRow(query, id).Scan(
				&p.ID, &p.Title, &p.Content, &p.OwnerID, &p.Author, &p.AuthorEmail, &p.CreatedAt, &p.UpdatedAt,
			)

			if err != nil {
				if err == sql.ErrNoRows {
					c.JSON(http.StatusNotFound, gin.H{"message": "post not found"})
					return
				}
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to load post"})
				return
			}

			c.JSON(http.StatusOK, PostResponse{Post: p})
		})

		protected.PUT("/posts/:id", func(c *gin.Context) {
			var request UpdatePostRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid update request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			query :=
				`
        			UPDATE posts 
        			SET title = ?, content = ?, updated_at = ? 
        			WHERE id = ? AND owner_id = ?
    			`

			id := c.Param("id")
			now := time.Now().Format(time.RFC3339)
			result, err := store.db.Exec(
				query, strings.TrimSpace(request.Title), strings.TrimSpace(request.Content), now, id, user.ID,
			)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to update post"})
				return
			}

			rowsAffected, _ := result.RowsAffected()
			if rowsAffected == 0 {
				c.JSON(http.StatusForbidden, gin.H{"message": "This post does not have editing permissions or does not exist"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "editing success",
				"post": gin.H{
					"id":         id,
					"title":      request.Title,
					"content":    request.Content,
					"updated_at": now,
				},
			})
		})

		protected.DELETE("/posts/:id", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			query :=
				`
					DELETE FROM posts 
					WHERE id = ? 
					AND owner_id = ?
				`

			result, err := store.db.Exec(query, id, user.ID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to delete post"})
				return
			}

			rowsAffected, _ := result.RowsAffected()
			if rowsAffected == 0 {
				c.JSON(http.StatusForbidden, gin.H{"message": "This is a post for which you do not have permission to delete"})
				return
			}

			id := c.Param("id")
			c.JSON(http.StatusOK, gin.H{
				"message": "post deleted",
				"id":      id,
			})
		})
	}

	if err := router.Run(":8080"); err != nil {
		panic(err)
	}
}

func openStore(databasePath, schemaFile, seedFile string) (*Store, error) {
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)

	store := &Store{db: db}
	if err := store.initialize(schemaFile, seedFile); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) close() error {
	return s.db.Close()
}

func (s *Store) initialize(schemaFile, seedFile string) error {
	if err := s.execSQLFile(schemaFile); err != nil {
		return err
	}
	if err := s.execSQLFile(seedFile); err != nil {
		return err
	}
	return nil
}

func (s *Store) execSQLFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(string(content))
	return err
}

func (s *Store) findUserByUsername(username string) (User, bool, error) {
	row := s.db.QueryRow(`
		SELECT id, username, name, email, phone, password, balance, is_admin
		FROM users
		WHERE username = ?
	`, strings.TrimSpace(username))

	var user User
	var isAdmin int64
	if err := row.Scan(&user.ID, &user.Username, &user.Name, &user.Email, &user.Phone, &user.Password, &user.Balance, &isAdmin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, false, nil
		}
		return User{}, false, err
	}
	user.IsAdmin = isAdmin == 1

	return user, true, nil
}

func newSessionStore() *SessionStore {
	return &SessionStore{
		tokens: make(map[string]User),
	}
}

func (s *SessionStore) create(user User) (string, error) {
	token, err := newSessionToken()
	if err != nil {
		return "", err
	}

	s.tokens[token] = user
	return token, nil
}

func (s *SessionStore) lookup(token string) (User, bool) {
	user, ok := s.tokens[token]
	return user, ok
}

func (s *SessionStore) delete(token string) {
	delete(s.tokens, token)
}

// fe 페이지 캐싱으로 테스트에 혼동이 있어, 별도 처리없이 main에 두시면 될 것 같습니다
// registerStaticRoutes 는 정적 파일(HTML, JS, CSS)을 제공하는 라우트를 등록한다.
func registerStaticRoutes(router *gin.Engine) {
	// 브라우저 캐시 비활성화 — 정적 파일과 루트 경로에만 적용
	router.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/static/") || c.Request.URL.Path == "/" {
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
			c.Header("Pragma", "no-cache")
			c.Header("Expires", "0")
		}
		c.Next()
	})
	router.Static("/static", "./static")
	router.GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})
}

func makeUserResponse(user User) UserResponse {
	return UserResponse{
		ID:       user.ID,
		Username: user.Username,
		Name:     user.Name,
		Email:    user.Email,
		Phone:    user.Phone,
		Balance:  user.Balance,
		IsAdmin:  user.IsAdmin,
	}
}

func clearAuthorizationCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(authorizationCookieName, "", -1, "/", "", false, true)
}

func tokenFromRequest(c *gin.Context) string {
	headerValue := strings.TrimSpace(c.GetHeader("Authorization"))
	if headerValue != "" {
		return headerValue
	}

	cookieValue, err := c.Cookie(authorizationCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookieValue)
}

func newSessionToken() (string, error) {
	buffer := make([]byte, 24)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
