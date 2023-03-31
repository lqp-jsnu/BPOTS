package test

import (
	"chainmaker.org/chainmaker/pb-go/v2/common"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	mrand "math/rand"
	"strconv"
	"transfer-client-go/client"
	"transfer-client-go/utils"
)

const (
	TestName = "TestSupplyChain1"
	tid      = "test.202303280007.tid.1"
	Pid      = "0000000000002023032800072222"
)

func CreateSupplyChainTest(client *client.TransferChainClient) {
	adminSk := utils.ReadKey("key/admin.key")
	result, err := client.CreateNewSupplyChain(TestName, &adminSk.PublicKey)
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println(result)
}

func AddPidTest(client *client.TransferChainClient) *common.TxResponse {
	adminSk := utils.ReadKey("key/admin.key")
	sk1 := utils.ReadKey("key/user2.key")
	response, err := client.AddNewPid(TestName, Pid, &sk1.PublicKey, adminSk)
	if err != nil {
		log.Fatal("e1" + err.Error())
	}
	return response
}

func CreateProductTest(client *client.TransferChainClient) *common.TxResponse {
	adminSk := utils.ReadKey("key/admin.key")
	//sk1 := utils.ReadKey("key/user1.key")

	result, err := client.CreateNewProduct(TestName, tid, Pid, adminSk)
	if err != nil {
		log.Fatal("e1" + err.Error())
	}
	return result

}

//174c8bf92e11885dcac174269add0f054c891baaf3d740f09f706a14f1e568e4
//174c8bf96d74f33cca52b32f991abcb986030ba522fa4955b0190fe133f1171b

func ReadSecretSingleTest(client *client.TransferChainClient) {
	txAlpha := "174c8bf92e11885dcac174269add0f054c891baaf3d740f09f706a14f1e568e4"
	txBeta := "174c8bf96d74f33cca52b32f991abcb986030ba522fa4955b0190fe133f1171b"
	ps := utils.ReadPrimeFromFile("prime/p20.txt")
	secretAlpha, opening1, err := client.ReadGamaByTxId(txAlpha, ps[1])
	if err != nil {
		log.Fatal("e1" + err.Error())
	}
	secretBeta, opening2, err := client.ReadGamaByTxId(txBeta, ps[1])
	if err != nil {
		log.Fatal("e1" + err.Error())
	}
	fmt.Println(secretAlpha, base64.StdEncoding.EncodeToString(opening1))
	fmt.Println(secretBeta, base64.StdEncoding.EncodeToString(opening2))
}

func UploadAlphaTest(client *client.TransferChainClient) *common.TxResponse {
	//adminSk := utils.ReadKey("key/admin.key")
	sk1 := utils.ReadKey("key/user2.key")
	//Pid := "00000000000000000000000000000000000000000000000000000000000000001111"
	var alpha = 1234567
	ps := utils.ReadPrimeFromFile("prime/p20.txt")

	miu1 := utils.BuildCRTKey(ps)
	opening1 := make([]byte, 32)
	opening2 := make([]byte, 32)
	_, _ = rand.Read(opening1)
	_, _ = rand.Read(opening2)

	txIdAlpha, err := client.UploadAlpha(miu1, uint64(alpha), TestName, tid, opening1, sk1)
	if err != nil {
		log.Fatal("e1" + err.Error())
	}
	return txIdAlpha
}

func UploadBetaTest(client *client.TransferChainClient) *common.TxResponse {
	adminSk := utils.ReadKey("key/admin.key")
	//Pid := "00000000000000000000000000000000000000000000000000000000000000001111"

	var beta = 7654321
	ps := utils.ReadPrimeFromFile("prime/p20.txt")

	miu2 := utils.BuildCRTKey(ps[0:2])

	opening1 := make([]byte, 32)
	opening2 := make([]byte, 32)
	_, _ = rand.Read(opening1)
	_, _ = rand.Read(opening2)

	txIdBeta, err := client.UploadBeta(miu2, uint64(beta), TestName, tid, opening2, adminSk)
	if err != nil {
		log.Fatal("e2" + err.Error())
	}
	return txIdBeta
}

func TransferSingleTest(chainClient *client.TransferChainClient) {
	txAlpha := "174c8bf92e11885dcac174269add0f054c891baaf3d740f09f706a14f1e568e4"
	txBeta := "174c8bf96d74f33cca52b32f991abcb986030ba522fa4955b0190fe133f1171b"
	ps := utils.ReadPrimeFromFile("prime/p20.txt")
	sk1 := utils.ReadKey("key/user2.key")
	pid := "00000000000000000000000000000000000000000000000000000000000000002222"
	tid := "test.tid.1"
	states := make([]client.TxState, 1)
	states[0] = client.NewTxState(tid, txAlpha, txBeta)
	_, err := chainClient.TransferProduct(TestName, states, ps[0], pid, sk1)
	if err != nil {
		log.Fatal("e1" + err.Error())
	}
}

func CreateBatchTest(chainClient *client.TransferChainClient) {
	adminSk := utils.ReadKey("key/admin.key")
	pid1 := "00000000000000000000000000000000000000000000000000000000000000001111"
	for i := 0; i < 10; i++ {
		tid := "test.000000.10." + strconv.Itoa(i)
		result, err := chainClient.CreateNewProduct(TestName, tid, pid1, adminSk)
		if err != nil {
			log.Fatal("create e1" + err.Error())
		}
		fmt.Println(tid, result)
	}
}

func BatchTransferUploadTest(chainClient *client.TransferChainClient, v bool) []client.TxState {
	adminSk := utils.ReadKey("key/admin.key")
	ps := utils.ReadPrimeFromFile("prime/p20.txt")
	miu1 := utils.BuildCRTKey(ps)
	miu2 := utils.BuildCRTKey(ps[0:2])
	var sk *ecdsa.PrivateKey
	if v {
		sk = utils.ReadKey("key/user1.key")
	} else {
		sk = utils.ReadKey("key/user2.key")
	}
	//pid2 := "00000000000000000000000000000000000000000000000000000000000000002222"
	//sk2 := utils.ReadKey("key/user2.key")
	//pid1 := "00000000000000000000000000000000000000000000000000000000000000001111"
	states := make([]client.TxState, 10)
	for i := 0; i < 10; i++ {
		alpha := mrand.Uint64() % 200000
		beta := mrand.Uint64() % 200000
		opening1 := make([]byte, 32)
		opening2 := make([]byte, 32)
		_, _ = rand.Read(opening1)
		_, _ = rand.Read(opening2)
		tid := "test.000000.10." + strconv.Itoa(i)
		txAlpha, err := chainClient.UploadAlpha(miu2, alpha, TestName, tid, opening1, sk)
		if err != nil {
			log.Fatal("upload e1" + err.Error())
		}
		txBeta, err := chainClient.UploadBeta(miu1, beta, TestName, tid, opening2, adminSk)
		if err != nil {
			log.Fatal("upload e2" + err.Error())
		}
		states[i] = client.NewTxState(tid, txAlpha.GetTxId(), txBeta.GetTxId())
	}
	return states
}

func BatchTransferTest(client *client.TransferChainClient, states []client.TxState, v bool) {
	ps := utils.ReadPrimeFromFile("prime/p20.txt")
	var sk *ecdsa.PrivateKey
	var pid string
	if v {
		sk = utils.ReadKey("key/user2.key")
		pid = "00000000000000000000000000000000000000000000000000000000000000002222"
	} else {
		sk = utils.ReadKey("key/user1.key")
		pid = "00000000000000000000000000000000000000000000000000000000000000001111"
	}
	_, err := client.TransferProduct(TestName, states, ps[0], pid, sk)
	if err != nil {
		log.Fatal("transfer e1" + err.Error())
	}

}
