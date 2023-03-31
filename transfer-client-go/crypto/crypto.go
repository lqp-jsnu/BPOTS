package crypto

import (
	"bytes"
	"chainmaker.org/chainmaker/common/v2/crypto/bulletproofs"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"transfer-client-go/utils"
)

const iv = "abcdabcdabcdabcd"

func Encrypt(miu *big.Int, secret uint64, opening []byte) ([]byte, []byte, error) {
	commit, err := bulletproofs.PedersenCommitSpecificOpening(secret, opening)
	if err != nil {
		return nil, nil, err
	}
	k := make([]byte, 16)
	_, err = rand.Read(k)
	if err != nil {
		return nil, nil, err
	}
	p := new(big.Int)
	p.SetBytes(k)
	p = p.Mul(p, miu)

	ciphertext := AesEncrypt(secret, opening, k)
	buffer := bytes.NewBuffer([]byte{})
	var length int32
	length = int32(len(ciphertext))
	_ = binary.Write(buffer, binary.BigEndian, length)
	_ = binary.Write(buffer, binary.BigEndian, ciphertext)
	_ = binary.Write(buffer, binary.BigEndian, p.Bytes())
	gama := buffer.Bytes()
	return gama, commit, nil
}

func Decrypt(key *big.Int, gama []byte) (uint64, []byte, error) {
	reader := bytes.NewReader(gama)
	var length int32

	err := binary.Read(reader, binary.BigEndian, &length)
	if err != nil {
		return 0, nil, err
	}

	len2 := int32(len(gama)) - length - 4
	ciphertext := make([]byte, length)

	_, err = reader.Read(ciphertext)
	if err != nil {
		return 0, nil, err
	}

	kc := make([]byte, len2)
	_, err = reader.Read(kc)
	if err != nil {
		return 0, nil, err
	}

	p := new(big.Int)
	p.SetBytes(kc)
	p = p.Mod(p, key)

	k := p.Bytes()
	if len(k) != 16 {
		k = utils.BytesCombine(make([]byte, 16-len(k)), k)
	}
	secret, opening := AesDecrypt(ciphertext, k)
	return secret, opening, nil
}

func AesEncrypt(value uint64, opening, key []byte) []byte {
	buffer := bytes.NewBuffer([]byte{})
	_ = binary.Write(buffer, binary.BigEndian, value)
	_ = binary.Write(buffer, binary.BigEndian, opening)
	block, _ := aes.NewCipher(key)
	encrypter := cipher.NewCBCEncrypter(block, []byte(iv))

	message := paddingBytes(buffer.Bytes(), block.BlockSize())
	ciphertext := make([]byte, len(message))
	encrypter.CryptBlocks(ciphertext, message)
	return ciphertext
}

func AesDecrypt(ciphertext, key []byte) (uint64, []byte) {
	block, _ := aes.NewCipher(key)
	decrypter := cipher.NewCBCDecrypter(block, []byte(iv))
	message := make([]byte, len(ciphertext))
	decrypter.CryptBlocks(message, ciphertext)
	message = unPaddingBytes(message)
	reader := bytes.NewReader(message)
	var secret uint64
	_ = binary.Read(reader, binary.BigEndian, &secret)
	opening := make([]byte, 32)
	_ = binary.Read(reader, binary.BigEndian, opening)
	return secret, opening
}

func paddingBytes(src []byte, blockSize int) []byte {
	//1.求出最后一个分组要填充多个字节
	padding := blockSize - len(src)%blockSize
	//2.创建新的切片，切片的字节数为填充的字节数，并初始化化，每个字节的值为填充的字节数
	padBytes := bytes.Repeat([]byte{byte(padding)}, padding)
	//3.将创建出的新切片和原始数据进行连接
	newBytes := append(src, padBytes...)

	//4.返回新的字符串
	return newBytes
}

//删除密文末尾分组填充的工具方法
func unPaddingBytes(src []byte) []byte {
	//1.求出要处理的切片的长度
	l := len(src)
	//2.取出最后一个字符，得到其整型值
	n := int(src[l-1])

	//3.将切片末尾的number个字节删除
	return src[:l-n]
}
