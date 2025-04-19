package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/alexedwards/scs/goredisstore"
	"github.com/alexedwards/scs/v2"
	"github.com/julienschmidt/httprouter"
	"github.com/knadh/koanf/parsers/dotenv"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"html/template"
	"log"
	"net/http"
	"time"
)

type App struct {
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
		Addr: "localhost:6380",
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

	config := &oauth2.Config{
		ClientID:     koanf.String("OAUTH_CLIENT_ID"),
		ClientSecret: koanf.String("OAUTH_CLIENT_SECRET"),
		RedirectURL:  koanf.String("OAUTH_REDIRECT_URL"),
		Scopes:       []string{"email", "profile"},
		Endpoint:     google.Endpoint,
	}

	app := App{
		Config: config,
		Rdb:    rdb,
		Scs:    sessionManager,
	}

	router.GET("/auth/login", app.LoginHandler)
	router.GET("/auth/logout", app.LogoutHandler)
	router.GET("/auth/oauth", app.OAuthHandler)
	router.GET("/auth/callback", app.OAuthCallBackHandler)
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

	// generate url for auth
	url := app.Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(writer, request, url, http.StatusTemporaryRedirect)
}

func (app *App) OAuthCallBackHandler(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
	url := request.URL.Query()
	log.Println(url)

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

	token, err := app.Config.Exchange(ctx, code)
	if err != nil {
		log.Fatalf("Failed to converts an authorization code into a token: %v", err)
	}

	//log.Println(token.AccessToken)
	//log.Println(token.RefreshToken)
	//log.Println(token.TokenType)
	//log.Println(token.Expiry)
	//log.Println(token.ExpiresIn)

	app.Scs.Put(ctx, "oauth_token", token.AccessToken)

	http.Redirect(writer, request, "https://a2a4-36-71-85-227.ngrok-free.app/dashboard", http.StatusSeeOther)
}

func (app *App) DashboardHandler(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
	ctx := request.Context()

	oauth_token := ctx.Value("oauth_token").(string)

	// get user info
	client := app.Config.Client(ctx, &oauth2.Token{
		AccessToken: oauth_token,
	})

	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()

	var userInfo map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&userInfo)
	if err != nil {
		log.Fatalf("Failed to decode json response: %v", err)
	}

	fmt.Fprintf(writer, "<h1>Welcome, %s!<h1><pre>%v<pre>", userInfo["name"], userInfo)
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
