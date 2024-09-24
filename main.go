package main

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/gorilla/sessions"
	"gopkg.in/yaml.v3"
)

// ____ ---- ____ ---- ____
// ---- setup & configs

var store *sessions.CookieStore

type FileItem struct {
	Name     string
	IsDir    bool
	ItemType string
}

type TemplateData struct {
	Files       []FileItem
	CurrentPath string
}

// for now leave as is, assigning from the globalConfig
// to not replace in all the funcs
var defaultDir string
var templateDir = "./templates"

// setup configs
type Config struct {
	Defaults struct {
		StorageLocation string `yaml:"storage_location"`
	} `yaml:"defaults"`
	UserCreds struct {
		User string `yaml:"user"`
	} `yaml:"user_creds"`
	Session struct {
		Secret string `yaml:"secret"`
	} `yaml:"session"`
}

func LoadConfig(filename string) (*Config, error) {
	config := &Config{}

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(config); err != nil {
		return nil, err
	}

	return config, nil
}

var globalConfig *Config

// cache the HTML templates
var templates = template.Must(template.ParseFiles(
	path.Join(templateDir, "file_view.html"),
	path.Join(templateDir, "file_upload_view.html"),
	path.Join(templateDir, "sidebar.html"),
	path.Join(templateDir, "clipboard_view.html"),
	path.Join(templateDir, "login_view.html"),
))

var clipboardContent string

// ____ ---- ____ ---- ____
// ---- template rendering

func renderFilesTemplate(w http.ResponseWriter, tmpl string, files []FileItem, currentPath string) {
	data := TemplateData{
		Files:       files,
		CurrentPath: currentPath,
	}

	err := templates.ExecuteTemplate(w, tmpl+".html", data)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func renderTemplateWithText(w http.ResponseWriter, tmpl string, text string) {
	err := templates.ExecuteTemplate(w, tmpl+".html", text)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// ____ ---- ____ ---- ____
// ---- file system management

func getFileType(pathname fs.DirEntry) string {
	if !pathname.IsDir() {
		extension := path.Ext(pathname.Name())

		switch extension {
		case ".doc", ".docx", ".txt", ".rtf":
			return "doc"
		case ".pdf":
			return "pdf"
		case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff":
			return "img"
		case ".mp3", ".wav", ".ogg", ".flac", ".aac":
			return "audio"
		case ".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv":
			return "video"
		default:
			return "other"
		}
	} else {
		return "dir"
	}
}

func listFiles(filesDir string) ([]FileItem, error) {
	files, err := os.ReadDir(filesDir)
	if err != nil {
		return nil, err
	}

	var FileItems []FileItem
	for _, file := range files {
		FileItems = append(
			FileItems,
			FileItem{
				Name:     file.Name(),
				IsDir:    file.IsDir(),
				ItemType: getFileType(file)},
		)
	}

	return FileItems, nil
}

func sanitizeFilename(filename string) string {
	// Replace spaces with underscores
	filename = strings.ReplaceAll(filename, " ", "-")

	// Drop not allowed symbols with regex
	reg := regexp.MustCompile(`[^a-zA-Z0-9_\-.]`)
	filename = reg.ReplaceAllString(filename, "")

	// Trim trailing dots or spaces
	filename = strings.Trim(filename, ". ")

	// in case of blank filename, use default name
	if filename == "" {
		currentTime := time.Now()
		filename = "new_file" + currentTime.Format("20060102_150405")
	}

	return filename
}

func fileServeHandler(w http.ResponseWriter, r *http.Request) {

	relativePath := r.URL.Path[len("/files/"):]
	fullPath := filepath.Join(defaultDir, relativePath)

	// debug
	log.Printf("Trying to access %s, relpath '%s'", fullPath, relativePath)

	// Check if file exists and is not a directory
	fileInfo, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	if fileInfo.IsDir() {
		files, err := listFiles(fullPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		renderFilesTemplate(w, "file_view", files, relativePath)

	} else {
		// Serve the file
		http.ServeFile(w, r, fullPath)
	}
}

func fileUploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {

		// Parse the multipart form:
		err := r.ParseMultipartForm(100 << 20) // cap max filesize 100 MB
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Get the file from form data
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer file.Close()

		uploadPath := r.FormValue("uploadPath")
		fullUploadPath := filepath.Join(defaultDir, uploadPath)

		// debug
		// log.Printf("Trying to upload file on %s", fullUploadPath)

		// check the possible issues with upload path not existing
		dirInfo, err := os.Stat(fullUploadPath)
		if err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "Upload directory does not exist", http.StatusBadRequest)
			} else {
				http.Error(w, "Error checking upload directory", http.StatusInternalServerError)
			}
			return
		}

		// Check if it's actually a directory
		if !dirInfo.IsDir() {
			http.Error(w, "Specified path is not a directory", http.StatusBadRequest)
			return
		}

		// Create a new file in the uploads directory
		sanitizedFilename := sanitizeFilename(header.Filename)

		dst, err := os.Create(filepath.Join(fullUploadPath, sanitizedFilename))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer dst.Close()

		// Copy the uploaded file to the filesystem
		_, err = io.Copy(dst, file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// debug
		log.Printf("Upload successful: %s", sanitizedFilename)

		http.Redirect(w, r, "/files/"+uploadPath, http.StatusSeeOther)

	} else {
		currentPath := r.URL.Query().Get("path")

		renderTemplateWithText(w, "file_upload_view", currentPath)
	}
}

func clipboardViewHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}

		newClipboardContent := r.FormValue("clipboardInput")
		clipboardContent = newClipboardContent

		http.Redirect(w, r, "/clipboard/", http.StatusSeeOther)
		return

	} else {
		renderTemplateWithText(w, "clipboard_view", clipboardContent)
	}
}

// ____ ---- ____ ---- ____
// ---- session & user login management

func generateRandomID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func setSession(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session.id")

	randomID := generateRandomID()

	session.Values["session_idstring"] = randomID
	session.Save(r, w)
}

func checkSession(r *http.Request) bool {
	session, _ := store.Get(r, "session.id")
	_, ok := session.Values["session_idstring"].(string)

	return ok
}

func emptySession(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session.id")
	delete(session.Values, "session_idstring")
	session.Save(r, w)
}

func authUser(username string, password string) bool {
	return username == "user" && password == globalConfig.UserCreds.User
}

func userLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "" || password == "" {
			renderTemplateWithText(w, "login_view", "")
		}

		userAuthenticated := authUser(username, password)
		if !userAuthenticated {
			renderTemplateWithText(w, "login_view", "LOGINERROR")
		}

		setSession(w, r)

		http.Redirect(w, r, "/files/", http.StatusSeeOther)
		return
	}

	renderTemplateWithText(w, "login_view", "")
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// don't redirect the login path itself
		if strings.HasPrefix(r.URL.Path, "/static/css/") ||
			r.URL.Path == "/login/" ||
			r.URL.Path == "/favicon.ico" {
			next.ServeHTTP(w, r)
			return
		}

		ok := checkSession(r)
		if !ok {
			http.Redirect(w, r, "/login/", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ____ ---- ____ ---- ____
// ---- server funcs

func getLocalIP() string {
	// read IP table to get local network IP
	// to access from other devices
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func runServer() {
	// get config
	// homeDir, err := os.UserHomeDir()
	// if err != nil {
	// 	log.Fatal("Error getting home directory: ", err)
	// }

	// configDir := filepath.Join(homeDir, ".config", "filegate")

	// TLS certs
	certPath := filepath.Join("./certs", "cert.pem")
	keyPath := filepath.Join("./certs", "key.pem")

	ip := getLocalIP()

	port := ":8000"
	router := http.NewServeMux()
	log.Printf("Server starting on %s%s ...\n", ip, port)

	// static files (CSS)
	router.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	router.HandleFunc("GET /login/", userLoginHandler)
	router.HandleFunc("POST /login/", userLoginHandler)

	router.HandleFunc("GET /files/", fileServeHandler)

	router.HandleFunc("GET /files/upload", fileUploadHandler)
	router.HandleFunc("POST /files/upload", fileUploadHandler)

	router.HandleFunc("GET /clipboard/", clipboardViewHandler)
	router.HandleFunc("POST /clipboard/", clipboardViewHandler)

	server := http.Server{
		Addr:    port,
		Handler: authMiddleware(router),
	}

	log.Fatal(server.ListenAndServeTLS(certPath, keyPath))
}

// ____ ---- ____ ---- ____
// ---- running the app

func init() {
	var err error
	globalConfig, err = LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	defaultDir = globalConfig.Defaults.StorageLocation

	store = sessions.NewCookieStore([]byte(globalConfig.Session.Secret))
}

func main() {
	runServer()
}
