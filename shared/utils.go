package shared

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// --- Helper Functions ---

func Pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

func EncryptPasswordAES(plainText string) (string, error) {
	key := []byte("8701661282118308")
	iv := []byte("8701661282118308")
	plaintextBytes := Pkcs7Pad([]byte(plainText), aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	cipherText := make([]byte, len(plaintextBytes))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, plaintextBytes)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func ExtractHiddenFields(body []byte) (string, string, error) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	viewState, exists1 := doc.Find("input[name='__VIEWSTATE']").Attr("value")
	eventValidation, exists2 := doc.Find("input[name='__EVENTVALIDATION']").Attr("value")
	if !exists1 || !exists2 {
		return "", "", fmt.Errorf("missing viewstate or eventvalidation")
	}
	return viewState, eventValidation, nil
}

func AuthenticateUser(username, password string) (*http.Client, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	loginURL := "https://webprosindia.com/vignanit/Default.aspx"
	resp, err := client.Get(loginURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get login page: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	viewState, eventValidation, err := ExtractHiddenFields(bodyBytes)
	if err != nil {
		return nil, err
	}
	encryptedPassword, err := EncryptPasswordAES(password)
	if err != nil {
		return nil, err
	}
	data := url.Values{}
	data.Set("__VIEWSTATE", viewState)
	data.Set("__EVENTVALIDATION", eventValidation)
	data.Set("txtId2", username)
	data.Set("hdnpwd2", encryptedPassword)
	data.Set("imgBtn2.x", "25")
	data.Set("imgBtn2.y", "10")
	req, _ := http.NewRequest("POST", loginURL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp2, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp2.Body.Close()
	loginBodyBytes, _ := io.ReadAll(resp2.Body)
	if strings.Contains(string(loginBodyBytes), "Invalid Username") {
		return nil, fmt.Errorf("invalid login")
	}
	return client, nil
}
