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
#include "wiringPi.h"
#include <time.h>

#cgo CFLAGS: -g
#cgo LDFLAGS: -lmbedtls -lmbedcrypto -lwiringPi
*/
import "C"
import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
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
	"strings"
	"time"
	"unsafe"

	"github.com/dhowden/raspicam"
)

const FILE_NAME = "video.mp4"
const SERVER_URL = "https://192.168.10.184:8443/upload"
const VIDEO_LENGTH = 600 // Video length in seconds

func main() {

	asciiArt := ` ________  ___  ________  ________  _____ ______   _______   ________  ________
|\   __  \|\  \|\   ____\|\   __  \|\   _ \  _   \|\  ___ \ |\   __  \|\   __  \
\ \  \|\  \ \  \ \  \___|\ \  \|\  \ \  \\\__\ \  \ \   __/|\ \  \|\  \ \  \|\  \
 \ \   ____\ \  \ \  \    \ \   __  \ \  \\|__| \  \ \  \_|/_\ \   _  _\ \   __  \
  \ \  \___|\ \  \ \  \____\ \  \ \  \ \  \    \ \  \ \  \_|\ \ \  \\  \\ \  \ \  \
   \ \__\    \ \__\ \_______\ \__\ \__\ \__\    \ \__\ \_______\ \__\\ _\\ \__\ \__\
    \|__|     \|__|\|_______|\|__|\|__|\|__|     \|__|\|_______|\|__|\|__|\|__|\|__|


                                                                                    `
	fmt.Printf("%s \n", asciiArt)

	C.picamera_init()

	pub_key_size := C.int(89)
	pub_key_c := C.CString(strings.Repeat("0", 89))

	error := C.picamera_genkey(pub_key_c, pub_key_size)
	if error != 0 {
		fmt.Println("error generating the keypair ")
	}
	defer C.free(unsafe.Pointer(pub_key_c))

	pubkey := C.GoString(pub_key_c)

	fmt.Printf("Public Key: %s \n", pubkey)
	fmt.Println("Please save the public key and press [enter] to continue...")
	fmt.Scanln()

	for {
		createVideo("video.264")
		convertVideo("video.264", FILE_NAME)
		go signAndSend(pubkey)
	}
}

func signAndSend(pubkey string) error {
	f, err := os.Open(FILE_NAME)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}
	hash := h.Sum(nil)

	signatureC := C.CString(strings.Repeat("0", 2048))
	error := C.int(0)
	error = C.picamera_get_signature(C.CString(string(hash)), signatureC)

	if error != 0 {
		fmt.Println("Error in Signature Generation")
	}

	signature := C.GoString(signatureC)
	fmt.Printf("Sending signature: %s", signature)

	fis, err := os.Create("signature")
	if err != nil {
		log.Fatal(err)
	}
	defer fis.Close()
	fis.Write([]byte(signature))

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
	postFile(SERVER_URL, "archive.tar")
	return nil
}

func createPicture(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return errors.New(fmt.Sprintf("Could not create picture %s, got error %s", filename, err.Error()))
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
	return nil
}

// Creates a video of 5 seconds (standard)
func createVideo(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create file: %v", err)
		return err
	}
	defer f.Close()

	s := raspicam.NewVid()
	s.Timeout = VIDEO_LENGTH * time.Second
	errCh := make(chan error)
	go func() {
		for x := range errCh {
			fmt.Fprintf(os.Stderr, "%v\n", x)
		}
	}()
	log.Println("Capturing video...")
	raspicam.Capture(s, f, errCh)
	return err
}

func convertVideo(input string, output string) error {
	cmd := exec.Command("ffmpeg", "-y", "-framerate", "30", "-i", input, "-c", "copy", output)
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	return err
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

// tar helper function from https://gist.github.com/maximilien/328c9ac19ab0a158a8df
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
