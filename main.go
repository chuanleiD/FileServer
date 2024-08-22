//go:generate goversioninfo
package main

import (
	"FileServer/util"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const contentDir = "./content"
const uploadDir = "./upload"
const listenPort = "18080"

var users = map[string]string{
	"admin": "admin",
	"user1": "userpass",
}

func main() {
	// 创建HTTP服务器
	mux := http.NewServeMux()
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/", authMiddleware(listFiles))
	mux.HandleFunc("/content/", authMiddleware(serveFile))

	// 配置HTTPS服务器
	server := &http.Server{
		Addr:         ":" + listenPort,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, // 设置最低支持的TLS版本为TLS 1.3
			MaxVersion: tls.VersionTLS13, // 设置最高支持的TLS版本为TLS 1.3
		},
	}

	ip, _ := util.GetWLANIPv4()
	fmt.Printf("Server is running on https://%s:%s\n", ip, listenPort)

	err := util.OpenBrowser("https://" + ip + ":" + listenPort)
	if err != nil {
		return
	}

	// 启动HTTPS服务器
	certFile, certFileKey := filepath.Join("config", "server.crt"), filepath.Join("config", "server.key")
	err = server.ListenAndServeTLS(certFile, certFileKey)
	if err != nil {
		log.Fatal(err)
	}
	return
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		html, err := os.ReadFile("html\\login2.html")
		if err != nil {
			http.Error(w, "Could not load login page", http.StatusInternalServerError)
			return
		}
		_, err = fmt.Fprint(w, string(html))
		if err != nil {
			return
		}
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
		//log.Println("Checking auth for:", r.URL.Path)
		next.ServeHTTP(w, r)
	}
}

func listFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		handleUpload(w, r)
		return
	}

	files, err := os.ReadDir(contentDir)
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
	html, err := os.ReadFile("html/fileList.html")
	if err != nil {
		http.Error(w, "无法加载文件列表页面", http.StatusInternalServerError)
		return
	}

	t, err := template.New("fileList").Parse(string(html))
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
		http.Error(w, "服务器错误", http.StatusInternalServerError)
		log.Printf("获取内容目录绝对路径时出错: %v", err)
		return
	}

	absFilePath, err := filepath.Abs(requestedPath)
	if err != nil {
		http.Error(w, "无效的文件路径", http.StatusBadRequest)
		log.Printf("获取请求文件绝对路径时出错: %v", err)
		return
	}

	if !strings.HasPrefix(absFilePath, absContentDir) {
		http.Error(w, "拒绝访问", http.StatusForbidden)
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
		http.Error(w, "拒绝访问", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(absFilePath))
	http.ServeFile(w, r, absFilePath)
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	// Parse the multipart form data
	err := r.ParseMultipartForm(10 << 24) // 10 MB max
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get the file from the form data
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer func(file multipart.File) {
		err = file.Close()
		if err != nil {
			log.Printf("关闭文件时出错: %v", err)
		}
	}(file)

	// Create the file in the content directory
	dst, err := os.Create(filepath.Join(uploadDir, header.Filename))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer func(dst *os.File) {
		err = dst.Close()
		if err != nil {
			log.Printf("关闭文件时出错: %v", err)
		}
	}(dst)

	// Copy the uploaded file to the destination file
	_, err = io.Copy(dst, file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect back to the file list
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
