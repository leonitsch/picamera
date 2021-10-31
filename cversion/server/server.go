package main

import (
	"archive/tar"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const uploadPath = "./tmp"
const FILE_NAME = "video.mp4"

var maxUploadSize int
var dataPath string
var certPath string
var keyPath string
var url string
var cameraPublicKey string
var customPublicKey bool

func main() {
	setup_close_handler()

	flag.StringVar(&url, "url", ":8443", "specify the URL to listen on. Either use localhost:8443 or :8443")
	flag.StringVar(&dataPath, "data_path", "./data", "specify the path where the received files get stored")
	flag.StringVar(&certPath, "cert_path", "./cert.pem", "specifiy path of certificate including the certificate filename, example: /etc/picamera/cert.pem")
	flag.StringVar(&keyPath, "key_path", "./key.pem", "specify path of key including the key file name, example: /etc/picamera/key.pem")
	flag.StringVar(&cameraPublicKey, "camera_pk", "./data/key.pub", "specify path of the public key")

	flag.IntVar(&maxUploadSize, "upload_size", 200*1024*1024, "set allowed upload size, default is 200 MB")
	flag.Parse()

	if cameraPublicKey == "./data/key.pub" {
		cameraPublicKey = dataPath + "/key.pub"
		customPublicKey = false
	} else {
		customPublicKey = true
	}

	// Handler setup for the index Page
	http.HandleFunc("/upload", uploadFileHandler())
	http.HandleFunc("/", helloHandler())
	// Handler setup for the File Server page
	fs := http.FileServer(http.Dir(dataPath))
	http.Handle("/files/", http.StripPrefix("/files", fs))
	// Logging
	log.Print("Server running on " + url)
	log.Fatal(http.ListenAndServeTLS(url, certPath, keyPath, nil))
}

/*
Extracts all TAR Archives in the /tmp directory
*/
func unpack_material() error {
	archives, err := ioutil.ReadDir(uploadPath)
	if err != nil {
		log.Fatal(err)
	}
	for _, archive := range archives {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		dirpath := dataPath + "/" + timestamp
		err := os.Mkdir(dirpath, 0755)
		if err != nil {
			log.Fatal(err)
		}
		err = untar_archive(uploadPath+"/"+archive.Name(), dirpath)
		check(err)
		fmt.Println("Removing " + archive.Name())
		err = os.Remove(uploadPath + "/" + archive.Name())
		check(err)
	}
	return nil
}

/*
Write a welcome Message to the index page and lists all data files.
Data Files where the signature was successfully checked are marked with true. All other files are marked with false.
Return the a http.HandlerFunc
*/
func helloHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<h1><center>Welcome to the picamera Upload Server</center></h1><br>"))
		data_dirs, err := ioutil.ReadDir(dataPath)
		if err != nil {
			log.Fatal(err)
		}

		for _, data := range data_dirs {
			val, err := check_signature(dataPath + "/" + data.Name())
			check(err)
			w.Write([]byte("<center>" + data.Name() + "  " + strconv.FormatBool(val) + "</center>"))
		}
	})
}

/*
Create the HandlerFunc for the Fileupload
*/
func uploadFileHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse the multipart form
		if err := r.ParseMultipartForm(int64(maxUploadSize)); err != nil {
			fmt.Printf("Could not parse multipart form: %v \n", err)
			renderError(w, "CANT_PARSE_FORM", http.StatusInternalServerError)
			return
		}
		// check and parse form parameters
		file, fileheader, err := r.FormFile("uploadFile")
		if err != nil {
			renderError(w, "INVALID_FILE", http.StatusBadRequest)
			return
		}
		defer file.Close()
		// Validate Upload Size
		fileSize := fileheader.Size
		fmt.Printf("File size (bytes): %v \n", fileSize)
		if fileSize > int64(maxUploadSize) {
			renderError(w, "FILE_TO_BIG", http.StatusBadRequest)
			return
		}
		// Read the File into a byte array
		fileBytes, err := ioutil.ReadAll(file)
		if err != nil {
			renderError(w, "INVALID_FILE", http.StatusBadRequest)
			return
		}
		// detect file type
		detectedFileType := http.DetectContentType(fileBytes)
		switch detectedFileType {
		case "image/jpeg", "image/jpg":
		case "image/gif", "image/png":
		case "application/pdf":
		case "application/gzip":
		case "text/plain":
		case "application/octet-stream":
		default:
			renderError(w, "INVALID_FILE_TYPE", http.StatusBadRequest)
		}

		fileName := randToken(12)
		// fileEndings, err := mime.ExtensionsByType(detectedFileType)
		if err != nil {
			renderError(w, "CANT_READ_FILE_TYPE", http.StatusInternalServerError)
			return
		}
		newPath := filepath.Join(uploadPath, fileName+".tar")
		fmt.Printf("FileType: %s, File: %s \n", detectedFileType, newPath)

		// Write the File to the Server
		fmt.Printf("Create new File at Path: %s\n", newPath)
		newFile, err := os.Create(newPath)
		if err != nil {
			renderError(w, "CANT_CREATE_FILE", http.StatusInternalServerError)
			return
		}
		defer newFile.Close()
		if _, err := newFile.Write(fileBytes); err != nil {
			renderError(w, "CANT_WRITE_FILE", http.StatusInternalServerError)
			return
		}

		err = unpack_material()

		if err != nil {
			log.Fatal(err)
		}
		w.Write([]byte("SUCCESS"))
	})
}

func check_signature(data_path string) (bool, error) {
	signature, err := ioutil.ReadFile(data_path + "/signature")
	if err != nil {
		fmt.Println("error:", err)
		return false, err
	}
	signature, err = base64.StdEncoding.DecodeString(string(signature))
	check(err)
	var pk []byte
	if customPublicKey {
		pk = []byte(cameraPublicKey)
	} else {
		pk, err = ioutil.ReadFile(data_path + "/key.pub")
		check(err)
	}
	curve := elliptic.P256()
	pubKey := ecdsa.PublicKey{
		Curve: curve,
		X:     &big.Int{},
		Y:     &big.Int{},
	}

	pubkey_point, err := base64.StdEncoding.DecodeString(string(pk))
	if err != nil {
		fmt.Println("error:", err)
		return false, err
	}
	xBytes := pubkey_point[1:33]
	yBytes := pubkey_point[33:]
	pubKey.X = new(big.Int).SetBytes(xBytes)
	pubKey.Y = new(big.Int).SetBytes(yBytes)

	f, err := os.Open(data_path + "/" + FILE_NAME)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}
	hash := h.Sum(nil)
	fmt.Printf("pub_key: %s,hash: %s, signature: %s \n", hex.EncodeToString(pubkey_point), hex.EncodeToString(hash), hex.EncodeToString(signature))

	if ecdsa.VerifyASN1(&pubKey, hash, signature) {
		fmt.Println("Signature okay")
		return true, nil
	}
	return false, nil
}

func untar_archive(archivepath string, destpath string) error {
	a, err := os.Open(archivepath)
	if err != nil {
		return err
	}
	tarReader := tar.NewReader(a)
	if err != nil {
		return err
	}
	for {
		header, err := tarReader.Next()
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			log.Fatal("tar reader error", err)
			return err
		case header == nil:
			continue
		}
		target := filepath.Join(destpath + "/" + header.Name)
		f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
		fmt.Printf("File: %s \n", target)
		defer f.Close()
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, tarReader); err != nil {
			return err
		}
	}
}

func setup_close_handler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("Ctrl+C pressed in Terminal")
		cleanup()
		os.Exit(0)
	}()
}

func cleanup() {
	err := RemoveContents("./tmp")
	check(err)
	err = RemoveContents(dataPath)
	check(err)
}

func RemoveContents(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		err = os.RemoveAll(filepath.Join(dir, name))
		if err != nil {
			return err
		}
	}
	return nil
}

func renderError(w http.ResponseWriter, message string, statusCode int) {
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(message))
}
func randToken(len int) string {
	b := make([]byte, len)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
