package main

import (
	"chainmaker.org/chainmaker/pb-go/v2/common"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"sync"
	"time"
	"transfer-client-go/client"
	"transfer-client-go/test"
	"transfer-client-go/utils"
)

func main() {

	key := utils.ReadKey("key/admin.key")
	user := utils.ReadKey("key/user2.key")
	primes := utils.ReadPrimeFromFile("prime/p20.txt")
	miu2 := utils.BuildCRTKey(primes)
	miu1 := utils.BuildCRTKey(primes[0:3])
	//fmt.Println(str)
	chainClient, err := client.NewTransferChainClient("config/config.yml")
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println("success client init")

	var ws sync.WaitGroup
	group := 8
	size := 125
	ws.Add(group)
	tid, txAlpha, txBeta := utils.BatchPrepare("2023033018280000", size*group)
	for i := 0; i < group; i++ {
		st := i * size
		go Prepare(txAlpha, txBeta, tid, st, size, chainClient, ws.Done, key, user, miu2, miu1)
	}
	ws.Wait()
	fmt.Println("Prepare Ok")
	for i := 1; i <= 5; i++ {
		Transfer(txAlpha, txBeta, tid, 200*i, chainClient, primes[1], user)
	}

	//TestSingle("AddPid", chainClient, test.AddPidTest)
	//TestSingle("CreateProduct", chainClient, test.CreateProductTest)
	//TestSingle("UploadAlpha", chainClient, test.UploadAlphaTest)
	//TestSingle("UploadBeta", chainClient, test.UploadBetaTest)

	//
	////test.CreateSupplyChainTest(chainClient)
	//
	////test.AddPidTest(chainClient)
	//test.CreateProductTest(chainClient)
	//test.UploadSecretSingleTest(chainClient)
	//test.ReadSecretSingleTest(chainClient)
	//test.TransferSingleTest(chainClient)
	//test.CreateBatchTest(chainClient)
	//states := test.BatchTransferUploadTest(chainClient, false)
	//test.BatchTransferTest(chainClient, states, false)
	//height, err := chainClient.GetClientObject().GetCurrentBlockHeight()
	//if err != nil {
	//	log.Fatal(err.Error())
	//}
	//fmt.Println(height)
}

func TestSingle(name string, chainClient *client.TransferChainClient, f func(*client.TransferChainClient) *common.TxResponse) {
	st := time.Now().UnixNano()
	r := f(chainClient)
	en := time.Now().UnixNano()
	txId := r.TxId
	tx, err := chainClient.GetClientObject().GetTxByTxId(txId)
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println(name, en-st, tx.GetTransaction().Size(), tx.GetTransaction().Result.GetContractResult().GasUsed)
}

func Transfer(transactionsAlpha, transactionsBeta, tid []string, size int, chainClient *client.TransferChainClient, key *big.Int, user *ecdsa.PrivateKey) {
	st := time.Now().UnixNano()
	txState := client.TransferToTxState(tid, transactionsAlpha, transactionsBeta, size)
	r, err := chainClient.TransferProduct(test.TestName, txState, key, test.Pid, user)
	if err != nil {
		log.Fatal(err.Error())
	}
	en := time.Now().UnixNano()
	txId := r.TxId
	tx, err := chainClient.GetClientObject().GetTxByTxId(txId)
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println(size, en-st, tx.GetTransaction().Size(), tx.GetTransaction().Result.GetContractResult().GasUsed)
}

func Prepare(transactionsAlpha, transactionsBeta, tid []string, st, size int, chainClient *client.TransferChainClient, done func(), admin, user *ecdsa.PrivateKey, miu1, miu2 *big.Int) {
	defer done()
	for i := st; i < st+size; i++ {
		//_, err := chainClient.CreateNewProduct(test.TestName, tid[i], test.Pid, admin)
		//if err != nil {
		//	log.Fatal(err.Error())
		//}
		alpha := rand.Int() % 200000
		beta := rand.Int() % 200000
		opening1 := make([]byte, 32)
		opening2 := make([]byte, 32)
		rand.Read(opening1)
		rand.Read(opening2)
		txAlpha, err := chainClient.UploadAlpha(miu1, uint64(alpha), test.TestName, tid[i], opening1, user)
		if err != nil {
			i--
			fmt.Println(err.Error())
		}
		txBeta, err := chainClient.UploadBeta(miu2, uint64(beta), test.TestName, tid[i], opening1, admin)
		if err != nil {
			i--
			fmt.Println(err.Error())
		}
		transactionsAlpha[i] = txAlpha.GetTxId()
		transactionsBeta[i] = txBeta.GetTxId()
	}
}

//MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESfRK933BT1xZKpGA2eEXdLfqI4EmHOyEgp86HIgtwmDA3PVGNuvFt0MvY6xo2dGEOk7S1jsAhdRL7favj1JGrA==
