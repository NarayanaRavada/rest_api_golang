package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type APIServer struct {
	listenAddr string
	store      Storage
}

func NewAPIServer(listenAddr string, store Storage) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
		store:      store,
	}
}

func (s *APIServer) Run() {
	router := mux.NewRouter()

	/* routes */
    router.HandleFunc("/login", makeHttpHandleFunc(s.handleLogin))
	router.HandleFunc("/account", makeHttpHandleFunc(s.handleAccount))
	router.HandleFunc("/account/{id}", withJWTAuth(makeHttpHandleFunc(s.handleAccountById), s.store))
    router.HandleFunc("/transfer", makeHttpHandleFunc(s.handleTransfer))

	fmt.Println(time.Now().Format(time.DateTime), " server running on port", s.listenAddr)

	/* start the server */
	http.ListenAndServe(s.listenAddr, router)
}

/* login handlers */
func invalidCredentials(w http.ResponseWriter) error {
    return writeJSON(w, http.StatusNotFound, ApiError{ Error: "login failed, invalid credentials", })
} 

func (s *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) error {
    if r.Method != "POST" {
        return fmt.Errorf("method not allowed %s", r.Method)
    }

    req := LoginRequest{}
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        return invalidCredentials(w)
    }
    defer r.Body.Close()

    account, err := s.store.GetHashedPassword(req.Email)
    if err != nil {
        return invalidCredentials(w)
    }
    if err := bcrypt.CompareHashAndPassword([]byte(account.EncryptedPassword), []byte(req.Password)); err != nil {
        return invalidCredentials(w)
    }

    account, err = s.store.GetAccountByID(account.ID)
    token, err := createJWT(account)
    if err != nil {
        return err
    }
    fmt.Println("JWT token: ", token)

    return writeJSON(w, http.StatusOK, map[string]string{
        "message": "Login Successful",
        "accessToken": token,
    })
}

/* account handlers */
func (s *APIServer) handleAccount(w http.ResponseWriter, r *http.Request) error {
	if r.Method == "GET" {
		return s.handleGetAccounts(w, r)
	}
	if r.Method == "POST" {
		return s.handleCreateAccount(w, r)
	}
	return fmt.Errorf("method not allowed %s", r.Method)
}

func (s *APIServer) handleAccountById(w http.ResponseWriter, r *http.Request) error {
    if r.Method == "GET" {
        return s.handleGetAccountById(w, r)
    }
    if r.Method == "DELETE" {
        return s.handleDeleteAccount(w, r)
    }

    return fmt.Errorf("method not allowed %s", r.Method)
}

func (s *APIServer) handleGetAccounts(w http.ResponseWriter, r *http.Request) error {
	accounts, err := s.store.GetAllAccounts()
	if err != nil {
		return err
	}

	return writeJSON(w, http.StatusOK, accounts)
}

func (s *APIServer) handleGetAccountById(w http.ResponseWriter, r *http.Request) error {
	id, err := getID(r)
	if err != nil {
		return nil
	}
	account, err := s.store.GetAccountByID(id)
	if err != nil {
		return err
	}
    
	return writeJSON(w, http.StatusOK, account)
}

func (s *APIServer) handleCreateAccount(w http.ResponseWriter, r *http.Request) error {
    req := CreateAccountRequest{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return err
	}

	account, err := NewAccount(req.FirstName, req.LastName, req.Email, req.Password)
    if err != nil {
        return err
    }
	if err := s.store.CreateAccount(account); err != nil {
		return err
	}

    return writeJSON(w, http.StatusOK, account)
}

func (s *APIServer) handleDeleteAccount(w http.ResponseWriter, r *http.Request) error {
	id, err := getID(r)
	if err != nil {
		return nil
	}
	if err := s.store.DeleteAccount(id); err != nil {
		return err
	}

	return writeJSON(w, http.StatusOK, map[string]int{"deleted": id})
}

/* Transfer Handlers */
func (s *APIServer) handleTransfer(w http.ResponseWriter, r *http.Request) error {
    transferRequest := TransferRequest{}
    if err := json.NewDecoder(r.Body).Decode(&transferRequest); err != nil {
        return err
    }
    defer r.Body.Close()

	return writeJSON(w, http.StatusOK, transferRequest)
}

/* Middleware */
func withJWTAuth(handleFunc http.HandlerFunc, s Storage) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        fmt.Println("calling JWT Auth Middleware")

        tokenString := r.Header.Get("x-jwt-token")
        token, err := validateJWT(tokenString)
        if err != nil {
            permissionDenied(w)
            return
        }
        if !token.Valid {
            permissionDenied(w)
            return
        }
        userId, err := getID(r)
        if err != nil {
            permissionDenied(w)
            return
        }
        account, err := s.GetAccountByID(userId)
        if err != nil {
            permissionDenied(w)
            return
        }
        claims := token.Claims.(jwt.MapClaims)
        if account.Number != int64(claims["accountNumber"].(float64)) {
            permissionDenied(w)
            return 
        }

        handleFunc(w, r)
    }
}

func validateJWT(tokenString string) (*jwt.Token, error) {
    secret := os.Getenv("JWT_SECRET")
    return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok :=  token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
        }

        return []byte(secret), nil
    })
}

func createJWT(account *Account) (string, error) {
    cliams := jwt.MapClaims{
        "expiresAt": 15000,
        "accountNumber": account.Number,
    }
    secret := os.Getenv("JWT_SECRET")
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, cliams)
    return token.SignedString([]byte(secret))
}

/* helper functons */
func permissionDenied(w http.ResponseWriter) {
    writeJSON(w, http.StatusForbidden, ApiError{Error: "permission denied"})
}

func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

type apiFunc func(http.ResponseWriter, *http.Request) error

type ApiError struct {
	Error string `json:"error"`
}

func makeHttpHandleFunc(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			writeJSON(w, http.StatusBadRequest, ApiError{Error: err.Error()})
		}
	}
}

func getID(r *http.Request) (int, error) {
	idStr := mux.Vars(r)["id"]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return id, fmt.Errorf("invalid id given %s", idStr)
	}
	return id, nil
}
