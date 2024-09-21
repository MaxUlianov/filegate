package main

import (
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
)

type FileItem struct {
	Name     string
	IsDir    bool
	ItemType string
}

type TemplateData struct {
	Files       []FileItem
	CurrentPath string
}

var defaultDir = "./shared"

// cache the HTML templates
var templates = template.Must(template.ParseFiles(
	"templates/file_view.html",
	"templates/file_upload_view.html",
	"templates/sidebar.html",
	"templates/clipboard_view.html",
))

var clipboardContent string

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
		FileItems = append(FileItems, FileItem{Name: file.Name(), IsDir: file.IsDir(), ItemType: getFileType(file)})
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
	log.Printf("Trying to access file on %s, relpath '%s'", fullPath, relativePath)

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
		err := r.ParseMultipartForm(100 << 20) // Max memory 100 MB
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
		log.Printf("Trying to upload file on %s", fullUploadPath)

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

		// debug
		log.Printf("Added CB text: %s", clipboardContent)

		http.Redirect(w, r, "/clipboard/", http.StatusSeeOther)
		return

	} else {
		renderTemplateWithText(w, "clipboard_view", clipboardContent)
	}
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return strings.Split(localAddr.String(), ":")[0]
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

	router.HandleFunc("GET /files/", fileServeHandler)

	router.HandleFunc("GET /files/upload", fileUploadHandler)
	router.HandleFunc("POST /files/upload", fileUploadHandler)

	router.HandleFunc("GET /clipboard/", clipboardViewHandler)
	router.HandleFunc("POST /clipboard/", clipboardViewHandler)

	server := http.Server{
		Addr:    port,
		Handler: router,
	}

	log.Fatal(server.ListenAndServeTLS(certPath, keyPath))
}

func main() {
	runServer()
}
