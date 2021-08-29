package main

/*
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <stddef.h>
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/debug.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/bignum.h"
#include "mbedtls/pk.h"
#include "mbedtls/base64.h"
#include "mbedtls/error.h"
#include "picamera.h"

#cgo CFLAGS: -g 
#cgo LDFLAGS: -lmbedtls -lmbedcrypto
*/
import "C"
//import "unsafe"

import (
	"archive/tar"
	"bytes"
	// "crypto/ed25519"
	// "crypto/rand"
	"crypto/sha256"
	// "crypto/x509"
	// "encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"github.com/dhowden/raspicam"
	"time"
)

// const FILE_NAME = "test.jpg"
const FILE_NAME = "video.mp4"

func main() {

	C.picamera_init()
	C.picamera_genkey()

	fmt.Println("Please save the public key and press [enter] to continue...")
	fmt.Scanln() // wait for Enter Key

	for i:=0;i<10;i++{
			
		// Take a picture
		// createPicture(FILE_NAME)
		createVideo("video.264")
		convertVideo("video.264",FILE_NAME)
		// createPicture("pic.png")
		f, err := os.Open(FILE_NAME)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		// Create the Hash
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			log.Fatal(err)
		}
		hash := h.Sum(nil)
		// Sign the generated Hash
		// signature := ed25519.Sign(priv_key, hash)
		// fmt.Printf("Signature: %s \n", hex.EncodeToString(signature))
		signature := C.GoString(C.picamera_get_signature(C.CString(string(hash))))
		fmt.Println("Sending signature: %s \n", signature)

		fis, err := os.Create("signature")
		if err != nil {
			log.Fatal(err)
		}
		defer fis.Close()
		fis.Write([]byte(signature))

		// convert the public key
		// pubkey, err := x509.MarshalPKIXPublicKey(pub_key)
		// if err != nil {
		// 	log.Fatal(err)
		// }
		// fmt.Printf("Converted public key: %s \n", hex.EncodeToString(pubkey))
		pubkey := C.GoString(C.picamera_get_publickey())
		fmt.Println("Sending pubkey: %s \n", pubkey)
		// Create a File for the public key
		fi, err := os.Create("key.pub")
		if err != nil {
			log.Fatal(err)
		}
		defer fi.Close()
		fi.Write([]byte(pubkey))

		// Create an Tar Archive
		tarfile, err := os.Create("archive.tar")
		if err != nil {
			log.Fatal(err)
		}
		defer tarfile.Close()
		tarWriter := tar.NewWriter(tarfile)
		addFileToTarWriter(FILE_NAME, tarWriter)
		addFileToTarWriter("key.pub", tarWriter)
		addFileToTarWriter("signature", tarWriter)
		postFile("http://192.168.10.199:8080/upload", "archive.tar")
		d, err := time.ParseDuration("5s")
		if err != nil {
			panic(err)
		}
		time.Sleep(d)
	}
}

func createPicture(filename string) {
	f, err := os.Create(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create file: %v", err)
		return
	}
	defer f.Close()

	s := raspicam.NewStill()
	errCh := make(chan error)
	go func() {
		for x := range errCh {
			fmt.Fprintf(os.Stderr, "%v\n", x)
		}
	}()
	log.Println("Capturing image...")
	raspicam.Capture(s, f, errCh)
}

// Creates a video of 5 seconds (standard)
func createVideo(filename string) {
	f, err := os.Create(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create file: %v", err)
		return
	}
	defer f.Close()

	s := raspicam.NewVid()
	errCh := make(chan error)
	go func() {
		for x := range errCh {
			fmt.Fprintf(os.Stderr, "%v\n", x)
		}
	}()
	log.Println("Capturing video...")
	raspicam.Capture(s, f, errCh)
}

func convertVideo(input string, output string){
	cmd := exec.Command("ffmpeg","-y","-framerate", "30", "-i", input, "-c", "copy" , output)
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
}



// Posts a file to the Server
func postFile(url string, file_path string) {
	method := "POST"

	payload := &bytes.Buffer{}
	writer := multipart.NewWriter(payload)
	file, errFile1 := os.Open(file_path)
	defer file.Close()
	part1,
		errFile1 := writer.CreateFormFile("uploadFile", filepath.Base(file_path))
	_, errFile1 = io.Copy(part1, file)
	if errFile1 != nil {

		fmt.Println(errFile1)
	}
	err := writer.Close()
	if err != nil {
		fmt.Println(err)
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("FORMAT TYPE: %s \n", writer.FormDataContentType())
	req.Header.Set("Content-Type", writer.FormDataContentType())
	res, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)

	fmt.Println(string(body))
}

// TAR HELPER FUNCTION
func addFileToTarWriter(filePath string, tarWriter *tar.Writer) error {
	file, err := os.Open(filePath)
	if err != nil {
		return errors.New(fmt.Sprintf("Could not open file '%s', got error '%s'", filePath, err.Error()))
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return errors.New(fmt.Sprintf("Could not get stat for file '%s', got error '%s'", filePath, err.Error()))
	}

	header := &tar.Header{
		Name:    filePath,
		Size:    stat.Size(),
		Mode:    int64(stat.Mode()),
		ModTime: stat.ModTime(),
	}

	err = tarWriter.WriteHeader(header)
	if err != nil {
		return errors.New(fmt.Sprintf("Could not write header for file '%s', got error '%s'", filePath, err.Error()))
	}

	_, err = io.Copy(tarWriter, file)
	if err != nil {
		return errors.New(fmt.Sprintf("Could not copy the file '%s' data to the tarball, got error '%s'", filePath, err.Error()))
	}

	return nil
}
