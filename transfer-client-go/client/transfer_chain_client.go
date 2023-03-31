package client

import (
	"chainmaker.org/chainmaker/common/v2/crypto/bulletproofs"
	"chainmaker.org/chainmaker/pb-go/v2/common"
	sdk "chainmaker.org/chainmaker/sdk-go/v2"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"transfer-client-go/crypto"
	"transfer-client-go/sign"
	"transfer-client-go/utils"
)

type TransferChainClient struct {
	client *sdk.ChainClient
}

type TxState struct {
	tid     string
	txAlpha string
	txBeta  string
}

const (
	ADD_PID        = "AddPid"
	CREATE_PRODUCT = "CreateProduct"
	UPLOAD_ALPHA   = "UploadAlpha"
	UPLOAD_BETA    = "UploadBeta"
	BATCH_TRANSFER = "ProductTransfer"
)

func NewTransferChainClient(configFile string) (*TransferChainClient, error) {
	p := new(TransferChainClient)
	var err error
	p.client, err = sdk.NewChainClient(sdk.WithConfPath(configFile))
	if err != nil {
		return nil, err
	}
	err = p.client.EnableCertHash()
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (t *TransferChainClient) GetClientObject() *sdk.ChainClient {
	return t.client
}

//CreateNewSupplyChain 创建新的供应链
//supplyChainId 供应链ID
func (t *TransferChainClient) CreateNewSupplyChain(supplyChainId string, adminPk *ecdsa.PublicKey) (*common.TxResponse, error) {
	chainClient := t.client
	pair := make([]*common.KeyValuePair, 1)
	str := utils.GenerateBase64AdminPk(adminPk)
	pair[0] = &common.KeyValuePair{Key: "admin", Value: []byte(str)}
	payload, err := chainClient.CreateContractCreatePayload("SC"+supplyChainId, "1.0.0", "transfer-contract-go.7z", common.RuntimeType_DOCKER_GO, pair)
	if err != nil {
		return nil, err
	}
	endorsementEntry, err := chainClient.SignContractManagePayload(payload)
	if err != nil {
		return nil, err
	}

	response, err := chainClient.SendContractManageRequest(payload, []*common.EndorsementEntry{endorsementEntry}, 10000000, true)
	if err != nil {
		return nil, err
	}
	return response, nil
}

//CreateNewProduct 创建产品
//supplyChainId 供应链ID
//tid 产品ID
func (t *TransferChainClient) CreateNewProduct(supplyChainId, tid, pid string, adminSk *ecdsa.PrivateKey) (*common.TxResponse, error) {
	pair := utils.NewKeyValuePair(4)
	tidBytes := []byte(tid)
	pidBytes := []byte(pid)
	utils.AddKeyValue(pair, 0, "tid", tidBytes)
	utils.AddKeyValue(pair, 1, "pid", pidBytes)
	r, s, err := sign.Sign(utils.BytesCombine(tidBytes, pidBytes), adminSk)
	if err != nil {
		return nil, err
	}
	utils.AddKeyValue(pair, 2, "r", r)
	utils.AddKeyValue(pair, 3, "s", s)
	response, err := t.InvokeContract(supplyChainId, CREATE_PRODUCT, pair)
	if err != nil {
		return nil, err
	}
	return response, nil
}

//AddNewPid 创建产品
//pid 伪ID
//pk 伪ID对应公钥
func (t *TransferChainClient) AddNewPid(supplyChainId string, pid string, pk *ecdsa.PublicKey, adminSk *ecdsa.PrivateKey) (*common.TxResponse, error) {
	p := utils.NewKeyValuePair(4)
	pkBytes, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, err
	}
	pidBytes := []byte(pid)
	r, s, err := sign.Sign(utils.BytesCombine(pidBytes, pkBytes), adminSk)
	if err != nil {
		return nil, err
	}
	utils.AddKeyValue(p, 0, "pid", pidBytes)
	utils.AddKeyValue(p, 1, "pk", pkBytes)
	utils.AddKeyValue(p, 2, "r", r)
	utils.AddKeyValue(p, 3, "s", s)
	response, err := t.InvokeContract(supplyChainId, ADD_PID, p)
	if err != nil {
		return nil, nil
	}
	return response, nil
}

func (t *TransferChainClient) UploadAlpha(miu *big.Int, secret uint64, supplyChainId, tid string, opening []byte, sk *ecdsa.PrivateKey) (*common.TxResponse, error) {
	return t.uploadSecret(UPLOAD_ALPHA, miu, secret, supplyChainId, tid, opening, sk)
}

func (t *TransferChainClient) UploadBeta(miu *big.Int, secret uint64, supplyChainId, tid string, opening []byte, sk *ecdsa.PrivateKey) (*common.TxResponse, error) {
	return t.uploadSecret(UPLOAD_BETA, miu, secret, supplyChainId, tid, opening, sk)
}

func (t *TransferChainClient) uploadSecret(functionName string, miu *big.Int, secret uint64, supplyChainId, tid string, opening []byte, sk *ecdsa.PrivateKey) (*common.TxResponse, error) {
	pair := utils.NewKeyValuePair(5)
	tidBytes := []byte(tid)
	gama, commit, err := crypto.Encrypt(miu, secret, opening)
	if err != nil {
		return nil, err
	}
	r, s, err := sign.Sign(utils.BytesCombine(tidBytes, gama, commit), sk)
	if err != nil {
		return nil, err
	}
	utils.AddKeyValue(pair, 0, "tid", tidBytes)
	utils.AddKeyValue(pair, 1, "gama", gama)
	utils.AddKeyValue(pair, 2, "commit", commit)
	utils.AddKeyValue(pair, 3, "r", r)
	utils.AddKeyValue(pair, 4, "s", s)
	response, err := t.InvokeContract(supplyChainId, functionName, pair)
	if err != nil {
		return nil, err
	}
	if response.GetCode() != 0 {
		return nil, fmt.Errorf("tx execute fail:" + response.GetMessage())
	}
	return response, nil
}

func (t *TransferChainClient) ReadGamaByTxId(txId string, s *big.Int) (uint64, []byte, error) {
	tx, err := t.client.GetTxByTxId(txId)
	if err != nil {
		return 0, nil, err
	}
	gama := tx.GetTransaction().GetPayload().GetParameter("gama")
	return crypto.Decrypt(s, gama)
}

func (t *TransferChainClient) TransferProduct(supplyChainId string, states []TxState, key *big.Int, pid string, sk *ecdsa.PrivateKey) (*common.TxResponse, error) {
	var pSecret uint64 = 0
	openings := make([]byte, 32)
	var tids []string
	for i := range states {
		state := states[i]
		tids = append(tids, state.tid)
		alpha, opening1, err := t.ReadGamaByTxId(state.txAlpha, key)
		if err != nil {
			return nil, err
		}
		beta, opening2, err := t.ReadGamaByTxId(state.txAlpha, key)
		if err != nil {
			return nil, err
		}
		pSecret = pSecret + alpha + beta
		tpOpening, _ := bulletproofs.PedersenAddOpening(opening1, opening2)
		tpScOpening, _ := bulletproofs.PedersenAddOpening(tpOpening, openings)
		openings = tpScOpening
	}
	tidsByte := utils.EncodeTids(tids)
	pidBytes := []byte(pid)
	pair := utils.NewKeyValuePair(6)
	pSecretBytes := utils.Uint64ToBytes(pSecret)
	utils.AddKeyValue(pair, 0, "tid", tidsByte)
	utils.AddKeyValue(pair, 1, "pid", pidBytes)
	utils.AddKeyValue(pair, 2, "pSecret", pSecretBytes)
	utils.AddKeyValue(pair, 3, "opening", openings)
	r, s, err := sign.Sign(utils.BytesCombine(pidBytes, tidsByte, pSecretBytes, openings), sk)
	if err != nil {
		return nil, err
	}
	utils.AddKeyValue(pair, 4, "r", r)
	utils.AddKeyValue(pair, 5, "s", s)
	response, err := t.InvokeContract(supplyChainId, BATCH_TRANSFER, pair)
	if err != nil {
		return nil, err
	}
	if response.GetCode() != 0 {
		return nil, fmt.Errorf("tx execute fail:" + response.GetMessage())
	}
	return response, nil
}

func (t *TransferChainClient) InvokeContract(supplyChainId, functionName string, p []*common.KeyValuePair) (*common.TxResponse, error) {
	return t.client.InvokeContract("SC"+supplyChainId, functionName, "", p, 10000, true)
}

func NewTxState(tid, alphaTx, betaTx string) TxState {
	return TxState{tid, alphaTx, betaTx}
}

func TransferToTxState(tid, txAlpha, txBeta []string, size int) []TxState {
	states := make([]TxState, size)
	for i := 0; i < size; i++ {
		states[i] = NewTxState(tid[i], txAlpha[i], txBeta[i])
	}
	return states
}
