package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

func CalcSha256(content []byte) []byte {
	hash := sha256.New()
	hash.Write(content)
	return hash.Sum(nil)
}

func DecodeTid(tids []byte) ([]string, error) {
	reader := bytes.NewReader(tids)
	var length int32
	err := binary.Read(reader, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	tidList := make([]string, length)
	for i := 0; i < int(length); i++ {
		var tidLen int32
		err := binary.Read(reader, binary.BigEndian, &tidLen)
		if err != nil {
			return nil, err
		}
		tid := make([]byte, tidLen)
		err = binary.Read(reader, binary.BigEndian, tid)
		if err != nil {
			return nil, err
		}
		tidList[i] = string(tid)
	}
	return tidList, nil
}

func BytesCombine(pBytes ...[]byte) []byte {
	return bytes.Join(pBytes, []byte(""))
}

func BytesToUint64(content []byte) uint64 {
	reader := bytes.NewReader(content)
	var x uint64
	_ = binary.Read(reader, binary.BigEndian, &x)
	return x
}
