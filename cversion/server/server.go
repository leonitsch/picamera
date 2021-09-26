package main

import (
	"archive/tar"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
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

// Upload Parameters
const maximumUploadSize = 20 * 1024 * 1024 // 10 MB
const uploadPath = "./tmp"

// const FILE_NAME = "test.jpg"
const FILE_NAME = "video.mp4"

func main() {
	setup_close_handler()
	// Handler setup for the index Page
	http.HandleFunc("/upload", uploadFileHandler())
	http.HandleFunc("/", helloHandler())
	// Handler setup for the File Server page
	fs := http.FileServer(http.Dir("./data"))
	http.Handle("/files/", http.StripPrefix("/files", fs))
	// Logging
	log.Print("Server startet on localhost:8443")
	log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil))
}

/*
Function
*/
func unpack_material() error {
	archives, err := ioutil.ReadDir("./tmp")
	if err != nil {
		log.Fatal(err)
	}
	for _, archive := range archives {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		dirpath := "./data/" + timestamp
		err := os.Mkdir(dirpath, 0755)
		if err != nil {
			log.Fatal(err)
		}
		err = untar_archive("./tmp/"+archive.Name(), dirpath)
		check(err)
		fmt.Println("REmove: " + archive.Name())
		err = os.Remove("./tmp/" + archive.Name())
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
		w.Write([]byte("<h1><center>Willkommen zum Raspberry PI Upload Server</center></h1><br>"))
		data_dirs, err := ioutil.ReadDir("./data")
		if err != nil {
			log.Fatal(err)
		}

		for _, data := range data_dirs {
			val, err := check_signature("./data/" + data.Name())
			check(err)
			w.Write([]byte("<center>" + data.Name() + "  " + strconv.FormatBool(val) + "</center>"))
		}
		// check_all_signatures()
	})
}

/*
Create the HandlerFunc for the Fileupload
*/
func uploadFileHandler() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse the multipart form
		if err := r.ParseMultipartForm(maximumUploadSize); err != nil {
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
		if fileSize > maximumUploadSize {
			renderError(w, "FILE_TO_BIG", http.StatusBadRequest)
			return
		}
		// Read the File into a byte array
		fileBytes, err := ioutil.ReadAll(file)
		if err != nil {
			renderError(w, "INVALID_FILE", http.StatusBadRequest)
			return
		}
		// detec file type
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

// func check_signature(data_path string) (bool, error) {
// 	signature, err := ioutil.ReadFile(data_path + "/signature")
// 	check(err)
// 	pk, err := ioutil.ReadFile(data_path + "/key.pub")
// 	check(err)
// 	pub_key, err := x509.ParsePKIXPublicKey(pk)
// 	check(err)
// 	f, err := os.Open(data_path + "/" + FILE_NAME)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer f.Close()

// 	h := sha256.New()
// 	if _, err := io.Copy(h, f); err != nil {
// 		log.Fatal(err)
// 	}
// 	hash := h.Sum(nil)
// 	fmt.Printf("pub_key: %s,hash: %s, signature: %s", hex.EncodeToString(pk), hex.EncodeToString(hash), hex.EncodeToString(signature))
// 	if ed25519.Verify(pub_key.(ed25519.PublicKey), hash, signature) {
// 		fmt.Println("Signature okay")
// 		return true, nil
// 	}
// 	return false, nil
// }

func check_signature(data_path string) (bool, error) {
	signature, err := ioutil.ReadFile(data_path + "/signature")
	if err != nil {
		fmt.Println("error:", err)
		return false, err
	}
	signature, err = base64.StdEncoding.DecodeString(string(signature))
	check(err)
	pk, err := ioutil.ReadFile(data_path + "/key.pub")
	check(err)
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
	fmt.Printf("GO received public key:   %s\n", hex.EncodeToString(pubkey_point))

	xBytes := pubkey_point[1:33]
	fmt.Printf("GO received public key X: %s\n", hex.EncodeToString(xBytes))
	yBytes := pubkey_point[33:]
	fmt.Printf("GO received public key Y: %s\n", hex.EncodeToString(yBytes))
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
	fmt.Printf("pub_key: %s,hash: %s, signature: %s", hex.EncodeToString(pubkey_point), hex.EncodeToString(hash), hex.EncodeToString(signature))

	if ecdsa.VerifyASN1(&pubKey, hash, signature) {
		fmt.Println("Signature okay")
		return true, nil
	}
	return false, nil
}

func check_all_signatures() {
	data_path := "./data/"
	data_dirs, err := ioutil.ReadDir(data_path)
	if err != nil {
		log.Fatal(err)
	}

	for _, data := range data_dirs {
		fmt.Println(data.Name())
		signature, err := ioutil.ReadFile(data_path + data.Name() + "/signature")
		check(err)
		pk, err := ioutil.ReadFile(data_path + data.Name() + "/key.pub")
		check(err)
		pub_key, err := x509.ParsePKIXPublicKey(pk)
		check(err)
		f, err := os.Open(data_path + data.Name() + "/" + FILE_NAME)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			log.Fatal(err)
		}
		hash := h.Sum(nil)
		fmt.Printf("pub_key: %s,hash: %s, signature: %s", hex.EncodeToString(pk), hex.EncodeToString(hash), hex.EncodeToString(signature))
		if ed25519.Verify(pub_key.(ed25519.PublicKey), hash, signature) {
			fmt.Println("Signature okay")
		} else {
			fmt.Println("WRONG")
		}
	}
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
		fmt.Printf("TargetFile: %s \n", target)
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
	err = RemoveContents("./data")
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
