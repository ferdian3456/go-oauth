package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alexedwards/scs/goredisstore"
	"github.com/alexedwards/scs/v2"
	"github.com/julienschmidt/httprouter"
	"github.com/knadh/koanf/parsers/dotenv"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type App struct {
	Koanf  *koanf.Koanf
	Config *oauth2.Config
	Rdb    *redis.Client
	Scs    *scs.SessionManager
}

func main() {
	router := httprouter.New()
	koanf := koanf.New(".")
	err := koanf.Load(file.Provider(".env"), dotenv.Parser())
	if err != nil {
		log.Fatal("Failed to load .env files")
	}

	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6389",
		DB:   0,
	})

	ctx := context.Background()

	err = rdb.Ping(ctx).Err()
	if err != nil {
		log.Fatalf("Failed to ping redis: %v", err)
	}

	log.Println("Connected to redis")

	sessionManager := scs.New()
	sessionManager.Store = goredisstore.New(rdb)

	sessionManager.Lifetime = 24 * time.Hour
	sessionManager.Cookie.Persist = true
	sessionManager.Cookie.SameSite = http.SameSiteLaxMode
	sessionManager.Cookie.Secure = true
	sessionManager.Cookie.HttpOnly = true
	sessionManager.IdleTimeout = 3 * time.Hour

	config := &oauth2.Config{
		ClientID:     koanf.String("OAUTH_CLIENT_ID"),
		ClientSecret: koanf.String("OAUTH_CLIENT_SECRET"),
		RedirectURL:  koanf.String("OAUTH_REDIRECT_URL"),
		Scopes:       []string{"email", "profile", "https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}

	app := App{
		Koanf:  koanf,
		Config: config,
		Rdb:    rdb,
		Scs:    sessionManager,
	}

	router.GET("/auth/login", app.LoginHandler)
	router.GET("/auth/logout", app.LogoutHandler)
	router.GET("/auth/oauth", app.OAuthHandler)
	router.GET("/auth/callback", app.OAuthCallBackHandler)
	router.POST("/auth/refresh", app.RefreshTokenHandler)
	router.GET("/dashboard", app.Middleware(app.DashboardHandler))

	server := http.Server{
		Addr:    ":8081",
		Handler: app.Scs.LoadAndSave(router),
	}

	log.Printf("Server is start on %s", server.Addr)

	err = server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start a server: %v", err)
	}
}

func generateState() string {
	b := make([]byte, 32)  // create a 32-byte slice
	_, err := rand.Read(b) // read b variable and fill it with secure random bytes
	if err != nil {
		log.Fatalf("Failed to generate state: %v", err)
	}

	return base64.URLEncoding.EncodeToString(b)
}

func (app *App) LoginHandler(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
	template, err := template.ParseFiles("login.html")
	if err != nil {
		log.Fatalf("Failed to parse template file: %v", err)
	}

	template.Execute(writer, nil)
}

func (app *App) LogoutHandler(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
	ctx := request.Context()

	app.Scs.Remove(ctx, "oauth_token")

	err := app.Scs.Destroy(ctx)
	if err != nil {
		log.Fatalf("Failed to remove session from session store: %v", err)
	}

	http.Redirect(writer, request, "/auth/login", http.StatusSeeOther)
}

func (app *App) OAuthHandler(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
	// generate random state
	state := generateState()

	// save state to redis
	ctx := request.Context()
	err := app.Rdb.Set(ctx, "oauth_state:"+state, true, 10*time.Minute).Err()
	if err != nil {
		log.Fatalf("Failed to store state in Redis: %v", err)
	}

	// Create custom auth URL with all required parameters
	authURL := app.Config.Endpoint.AuthURL
	values := url.Values{}
	values.Add("client_id", app.Config.ClientID)
	values.Add("redirect_uri", app.Config.RedirectURL)
	values.Add("scope", strings.Join(app.Config.Scopes, " "))
	values.Add("response_type", "code")
	values.Add("state", state)
	values.Add("access_type", "offline")
	values.Add("prompt", "consent")

	url := fmt.Sprintf("%s?%s", authURL, values.Encode())

	log.Printf("OAuth URL: %s", url)
	http.Redirect(writer, request, url, http.StatusTemporaryRedirect)
}

func (app *App) OAuthCallBackHandler(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
	//url := request.URL.Query()
	log.Println("Url: ", request.URL)

	code := request.URL.Query().Get("code")
	state := request.URL.Query().Get("state")

	if state == "" || code == "" {
		http.Error(writer, "State or code missing", http.StatusBadRequest)
		return
	}

	ctx := request.Context()

	_, err := app.Rdb.Exists(ctx, "oauth_state:"+state).Result()
	if err != nil {
		http.Error(writer, "Invalid or expired state", http.StatusBadRequest)
		return
	}

	err = app.Rdb.Del(ctx, "oauth_state:"+state).Err()
	if err != nil {
		log.Fatalf("Failed to delete state from Redis")
	}

	// Create a custom token request to ensure we get refresh token
	token, err := app.Config.Exchange(ctx, code, oauth2.AccessTypeOffline)
	if err != nil {
		log.Fatalf("Failed to converts an authorization code into a token: %v", err)
	}

	log.Println("Access Token: ", token.AccessToken)
	log.Println("Refresh Token: ", token.RefreshToken)
	log.Println("Token Type: ", token.TokenType)
	log.Println("Expiry: ", token.Expiry)
	
	// Calculate expires_in manually since Google doesn't provide it
	expiresIn := int64(token.Expiry.Sub(time.Now()).Seconds())
	log.Println("Expires In: ", expiresIn)

	// Store both access token and refresh token in session
	app.Scs.Put(ctx, "oauth_token", token.AccessToken)
	if token.RefreshToken != "" {
		app.Scs.Put(ctx, "refresh_token", token.RefreshToken)
	}

	http.Redirect(writer, request, app.Koanf.String("NGROK_URL")+"/dashboard", http.StatusSeeOther)
}

func (app *App) RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{
		RefreshToken: refreshToken,
	}
	
	tokenSource := app.Config.TokenSource(ctx, token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, err
	}
	
	return newToken, nil
}

func (app *App) RefreshTokenHandler(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
	// Parse request body
	var requestBody struct {
		RefreshToken string `json:"refresh_token"`
	}

	err := json.NewDecoder(request.Body).Decode(&requestBody)
	if err != nil {
		http.Error(writer, "Invalid request body", http.StatusBadRequest)
		return
	}

	if requestBody.RefreshToken == "" {
		http.Error(writer, "Refresh token is required", http.StatusBadRequest)
		return
	}

	// Use the refresh token to get new access token
	ctx := request.Context()
	newToken, err := app.RefreshToken(ctx, requestBody.RefreshToken)
	if err != nil {
		http.Error(writer, fmt.Sprintf("Failed to refresh token: %v", err), http.StatusInternalServerError)
		return
	}

	// Prepare response
	response := struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token,omitempty"`
	}{
		AccessToken:  newToken.AccessToken,
		TokenType:    newToken.TokenType,
		ExpiresIn:    int64(newToken.Expiry.Sub(time.Now()).Seconds()),
	}
	
	log.Printf("New token expires in: %d seconds", response.ExpiresIn)

	// Include refresh token in response if it's updated
	if newToken.RefreshToken != "" && newToken.RefreshToken != requestBody.RefreshToken {
		response.RefreshToken = newToken.RefreshToken
	}

	// Set response headers
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)

	// Send response
	json.NewEncoder(writer).Encode(response)
}

func (app *App) DashboardHandler(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
	ctx := request.Context()

	oauth_token := ctx.Value("oauth_token").(string)

	// Create token with access token
	token := &oauth2.Token{
		AccessToken: oauth_token,
	}

	// get user info
	client := app.Config.Client(ctx, token)

	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read all:%v", err)
	}

	var googleUser struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}

	err = json.Unmarshal(body, &googleUser)
	if err != nil {
		log.Fatalf("Failed to unmarshal :%v", err)
	}

	fmt.Println("User: ", googleUser)

	fmt.Fprintf(writer, "<h1>Welcome, %s!</h1><h2>Email: %s</h2><h2>Verified Email: %t</h2><h2>Picture Url: %s</h2>",
		googleUser.Name, googleUser.Email, googleUser.VerifiedEmail, googleUser.Picture)
}

func (app *App) Middleware(next httprouter.Handle) httprouter.Handle {
	return func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		ctx := request.Context()

		oauth_token := app.Scs.GetString(ctx, "oauth_token")

		if oauth_token == "" {
			http.Redirect(writer, request, "/auth/login", http.StatusSeeOther)
			return
		}

		ctx = context.WithValue(ctx, "oauth_token", oauth_token)

		request = request.WithContext(ctx)

		next(writer, request, params)
	}
}
