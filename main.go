package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
	"flag"
	"strconv"
	"os/exec"
	//"encoding/base64"
)

func create_dir(dir string) {
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		fmt.Println("Error creating directory:", dir, err)
		return
	}

	fmt.Println("Directory created successfully")
}

func ec2pem() {
	_, _= os.Create("cert/key.pem")
	cmd := exec.Command("openssl", "pkcs8", "-topk8", "-inform", "PEM", "-in", "cert/key-ec.pem", "-outform", "PEM", "-nocrypt", "-out", "cert/key.pem")
	_, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println("Error creating StdoutPipe for Cmd", err)
		return
	}

	if err := cmd.Start(); err != nil {
		fmt.Println("Error starting Cmd", err)
		return
	}

	if err := cmd.Wait(); err != nil {
		fmt.Println("Error waiting for Cmd", err)
		return
	}

	fmt.Println("Command finished successfully")
}

func main() {
	var inters int
	var domain string
	var port int
	var notgencert bool
	var noserver bool
	flag.StringVar(&domain, "domain", "localhost", "domain for ca to generate")
	flag.IntVar(&port, "port", 8423, "port to bind")
	flag.IntVar(&inters, "inters", 10, "Intermediate Certificate count")
	flag.BoolVar(&notgencert, "notgencert", false, "gen cert")
	flag.BoolVar(&noserver, "noserver", false, "not start server")
	flag.Parse()

	if !notgencert {
		fmt.Println("-domain ", domain, ", -port ", port, ", -inters ", inters)
		create_dir("./cert/")
		privPem, chainPem := makePathologicalChain(domain, inters)
		f, _:= os.Create("cert/key-ec.pem")
		f.WriteString(privPem)
		f1,_:= os.Create("cert/chains.pem")
		f1.WriteString(chainPem)
		ec2pem()
	}
	if noserver {
		return
	}
	if err := http.ListenAndServeTLS(":"+strconv.Itoa(port), "cert/chains.pem", "cert/key-ec.pem", nil); err != nil {
		log.Fatal(err)
	}
}

func EncodePrivateKeyToPem(key *ecdsa.PrivateKey) (string, error) {
	// 获取私钥的二进制编码
	kb:= key.D.Bytes()

	// 将DER编码的数据转换为base64编码
	//b64Bytes := make([]byte, base64.StdEncoding.EncodedLen(len(kb)))
	//base64.StdEncoding.Encode(b64Bytes, kb)
	ret:= pemEncode(kb, "PRIVATE KEY")
	return ret,nil
}

// Adapted from Go 1.11.3 crypto/x509/verify_test.go:TestPathologicalChain
// Returns (privkeyPem, fullchainPem)
func makePathologicalChain(domain string, inters int) (string, string) {
	root, rootKey, err := generateCert("rootcn", true, nil, nil)
	if err != nil {
		log.Fatal(err)
	}

	fullchainReverse := []string{}
	rootca := pemEncode(root.Raw, "CERTIFICATE")
	f,err := os.Create("cert/root.pem")
	f.WriteString(rootca)

	fullchainReverse = append(fullchainReverse, rootca)

	for i := 0; i < inters; i++ {
		root, rootKey, err = generateCert("mid", true, root, rootKey)
		//root, rootKey, err = generateCert("mid"+strconv.Itoa(i), true, root, rootKey)
		if err != nil {
			log.Fatal(err)
		}
		fullchainReverse = append(fullchainReverse, pemEncode(root.Raw, "CERTIFICATE"))
	}

	leaf, leafKey, err := generateCert(domain, false, root, rootKey)
	if err != nil {
		log.Fatal(err)
	}
	fullchainReverse = append(fullchainReverse, pemEncode(leaf.Raw, "CERTIFICATE"))

	for i, j := 0, len(fullchainReverse)-1; i < j; i, j = i+1, j-1 {
		fullchainReverse[i], fullchainReverse[j] = fullchainReverse[j], fullchainReverse[i]
	}
	leafKeyDer, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		log.Fatal(err)
	}
	//ll,err:= EncodePrivateKeyToPem(leafKey)
	return pemEncode(leafKeyDer, "EC PRIVATE KEY"), strings.Join(fullchainReverse, "")
	//return ll, strings.Join(fullchainReverse, "")
}


// Copied from Go 1.11.3 crypto/x509/verify_test.go
func generateCert(cn string, isCA bool, issuer *x509.Certificate, issuerKey crypto.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if issuer == nil {
		issuer = template
		issuerKey = priv
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, issuer, priv.Public(), issuerKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func pemEncode(data []byte, t string) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  t,
		Bytes: data,
	}))
}
