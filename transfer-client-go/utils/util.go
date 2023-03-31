package utils

import (
	"bufio"
	"bytes"
	"chainmaker.org/chainmaker/pb-go/v2/common"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"log"
	"math/big"
	"os"
	"strconv"
)

func GenerateSignatureKeyAndSave(filename string) {
	adminSk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	skByte, err := x509.MarshalECPrivateKey(adminSk)
	if err != nil {
		log.Fatal("error")
	}
	open, err := os.Create(filename)
	if err != nil {
		log.Fatal(err.Error())
	}
	_, err = open.Write(skByte)
	if err != nil {
		log.Fatal(err.Error())
	}
}

func GenerateBase64AdminPk(pk *ecdsa.PublicKey) string {
	pkBytes, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		log.Fatal(err.Error())
	}
	return base64.StdEncoding.EncodeToString(pkBytes)
}

func ReadKey(filename string) *ecdsa.PrivateKey {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err.Error())
	}
	stat, _ := file.Stat()
	size := stat.Size()
	bytes := make([]byte, size)
	_, _ = file.Read(bytes)
	key, err := x509.ParseECPrivateKey(bytes)
	if err != nil {
		log.Fatal(key)
	}
	return key
}

func NewKeyValuePair(size int) []*common.KeyValuePair {
	return make([]*common.KeyValuePair, size)
}

func AddKeyValue(pairs []*common.KeyValuePair, index int, key string, value []byte) {
	pairs[index] = new(common.KeyValuePair)
	pairs[index].Key = key
	pairs[index].Value = value
}

func BytesCombine(pBytes ...[]byte) []byte {
	return bytes.Join(pBytes, []byte(""))
}

func BuildCRTKey(primes []*big.Int) *big.Int {
	p := big.NewInt(1)
	for i := 0; i < len(primes); i++ {
		p = p.Mul(p, primes[i])
	}
	miu := big.NewInt(0)
	for i := 0; i < len(primes); i++ {
		x := new(big.Int)
		y := new(big.Int)
		s := new(big.Int)
		x.Div(p, primes[i])
		y.ModInverse(x, primes[i])
		miu.Add(miu, s.Mul(x, y))
	}
	return miu
}

func GeneratePrimeAndSave(fileName string, number, bits int) {
	f, _ := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0644)
	for i := 0; i < number; i++ {
		p, _ := rand.Prime(rand.Reader, bits)
		text, _ := p.MarshalText()
		_, _ = f.WriteString(string(text) + "\n")
	}
}

func ReadPrimeFromFile(filename string) []*big.Int {
	var ps []*big.Int
	f, _ := os.Open(filename)
	reader := bufio.NewReader(f)
	var err error
	var prefix = false
	err = nil
	for err == nil && !prefix {
		var sb []byte
		sb, prefix, err = reader.ReadLine()
		if len(sb) != 0 {
			b := new(big.Int)
			_ = b.UnmarshalText(sb)
			ps = append(ps, b)
		}
	}
	return ps
}

func EncodeTids(tids []string) []byte {
	length := len(tids)
	buffer := bytes.NewBuffer([]byte{})

	err := binary.Write(buffer, binary.BigEndian, int32(length))
	if err != nil {
		log.Fatal("encode tid fail:" + err.Error())
	}
	for i := 0; i < length; i++ {
		tid := tids[i]
		tidLen := len(tid)
		tidBytes := []byte(tid)
		err := binary.Write(buffer, binary.BigEndian, int32(tidLen))
		if err != nil {
			log.Fatal("encode tid fail:" + err.Error())
		}
		err = binary.Write(buffer, binary.BigEndian, tidBytes)
		if err != nil {
			log.Fatal("encode tid fail:" + err.Error())
		}
	}
	return buffer.Bytes()
}

func Uint64ToBytes(v uint64) []byte {
	buffer := bytes.NewBuffer([]byte{})
	_ = binary.Write(buffer, binary.BigEndian, v)
	return buffer.Bytes()
}

func BatchPrepare(prefix string, size int) ([]string, []string, []string) {
	tid := make([]string, size)
	for i := 0; i < size; i++ {
		tid[i] = prefix + strconv.Itoa(i)
	}
	return tid, make([]string, size), make([]string, size)

}
