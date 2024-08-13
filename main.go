//go:generate goversioninfo
package main

import (
	"FileServer/util"
	"crypto/subtle"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const contentDir = "./content"

var users = map[string]string{
	"admin": "password123",
	"user1": "userpass",
}

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/", authMiddleware(listFiles))
	http.HandleFunc("/content/", authMiddleware(serveFile))

	ip, _ := util.GetWLANIPv4()
	fmt.Printf("Server is running on http://%s:8080\n", ip)

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `
			<form method="post" action="/login">
				Username: <input type="text" name="username"><br>
				Password: <input type="password" name="password"><br>
				<input type="submit" value="Login">
			</form>
		`)
		return
	}

	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if storedPassword, ok := users[username]; ok {
			if subtle.ConstantTimeCompare([]byte(password), []byte(storedPassword)) == 1 {
				http.SetCookie(w, &http.Cookie{
					Name:  "auth",
					Value: username,
					Path:  "/",
				})
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("auth")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		if _, ok := users[cookie.Value]; !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func listFiles(w http.ResponseWriter, r *http.Request) {
	files, err := ioutil.ReadDir(contentDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var fileLinks []string
	for _, file := range files {
		if !file.IsDir() {
			fileLinks = append(fileLinks, file.Name())
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := `
<!DOCTYPE html>
<html>
<head>
	<title>File List</title>
</head>
<body>
	<h1>Files in content directory:</h1>
	<ul>
	{{range .}}
		<li><a href="/content/{{.}}">{{.}}</a></li>
	{{end}}
	</ul>
</body>
</html>`

	t, err := template.New("fileList").Parse(tmpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = t.Execute(w, fileLinks)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func serveFile(w http.ResponseWriter, r *http.Request) {
	requestedPath := filepath.Join(contentDir, strings.TrimPrefix(r.URL.Path, "/content/"))

	absContentDir, err := filepath.Abs(contentDir)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		log.Printf("Error getting absolute path of content directory: %v", err)
		return
	}

	absFilePath, err := filepath.Abs(requestedPath)
	if err != nil {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		log.Printf("Error getting absolute path of requested file: %v", err)
		return
	}

	if !strings.HasPrefix(absFilePath, absContentDir) {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	info, err := os.Stat(absFilePath)
	if os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if info.IsDir() {
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	http.ServeFile(w, r, absFilePath)
}
