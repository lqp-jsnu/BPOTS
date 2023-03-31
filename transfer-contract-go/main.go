package main

import (
	"bytes"
	"chainmaker.org/chainmaker/common/v2/crypto/bulletproofs"
	"chainmaker.org/chainmaker/contract-sdk-go/v2/pb/protogo"
	"chainmaker.org/chainmaker/contract-sdk-go/v2/sandbox"
	"chainmaker.org/chainmaker/contract-sdk-go/v2/sdk"
	"encoding/base64"
	"encoding/binary"
	"log"
	"transfer-contract-go/ecdsa_pid"
	"transfer-contract-go/utils"
)

// OwnershipManagement 所有权管理
type OwnershipManagement struct {
}

//数据读写类代码
const (
	PidDomain    = "pid."
	CommitDomain = "commit."
	CipherDomain = "cipher."
	AdminPid     = "admin"
	OwnerDomain  = "owner"
)

func (p *OwnershipManagement) ReadState(key string) ([]byte, error) {
	return sdk.Instance.GetStateFromKeyByte(key)
}

func (p *OwnershipManagement) WriteState(key string, value []byte) error {
	return sdk.Instance.PutStateFromKeyByte(key, value)
}

func (p *OwnershipManagement) ReadArgs(key string) []byte {
	return sdk.Instance.GetArgs()[key]
}

func (p *OwnershipManagement) HasState(key string) bool {
	state, err := p.ReadState(key)
	if err != nil || len(state) == 0 {
		return false
	}
	return true
}

//智能合约接口代码

func (p *OwnershipManagement) InitContract() protogo.Response {
	pkBytes := p.ReadArgs("admin")
	pkStr := string(pkBytes)
	pk, err := base64.StdEncoding.DecodeString(pkStr)
	if err != nil {
		_ = p.WriteState("fail_reason", []byte(err.Error()))
		return sdk.Success([]byte("base64 analysis failure"))
	}
	err = p.writeAdminPk(pk)
	if err != nil {
		_ = p.WriteState("fail_reason", []byte(err.Error()))
		return sdk.Success([]byte("pk write fail"))
	}
	return sdk.Success([]byte("deploy success:" + pkStr))
}

func (p *OwnershipManagement) UpgradeContract() protogo.Response {
	return sdk.Success([]byte("success"))
}

func (p *OwnershipManagement) InvokeContract(method string) protogo.Response {
	switch method {
	case "AddPid":
		return p.AddPid()
	case "CreateProduct":
		return p.CreateProduct()
	case "UploadAlpha":
		return p.UploadAlpha()
	case "UploadBeta":
		return p.UploadBeta()
	case "ProductTransfer":
		return p.BatchTransfer()
	case "ReadCipher":
		return p.ReadCipherValue()
	case "ReadCipherBatch":
		return p.ReadCipherValueBatch()
	case "f":
		return p.ReadFailReason()
	default:
		return sdk.Error("no function named:" + method)
	}
}

//智能合约辅助代码

func (p *OwnershipManagement) BuildKey(domain string, index string) string {
	return domain + index
}

func (p *OwnershipManagement) BuildKeyWithAlpha(domain, index string, alpha bool) string {
	if alpha {
		return domain + "al." + index
	} else {
		return domain + "be." + index
	}
}

//ReadPkByPid 读取pid对应签名公钥
func (p *OwnershipManagement) ReadPkByPid(pid string) ([]byte, error) {
	return p.ReadState(p.BuildKey(PidDomain, pid))
}

func (p *OwnershipManagement) WritePkByPid(pid string, pk []byte) error {
	return p.WriteState(p.BuildKey(PidDomain, pid), pk)
}

func (p *OwnershipManagement) WriteCipher(tid string, alpha bool, cipher []byte) error {
	return p.WriteState(p.BuildKeyWithAlpha(CipherDomain, tid, alpha), cipher)
}

func (p *OwnershipManagement) ReadCipher(tid string, alpha bool) ([]byte, error) {
	return p.ReadState(p.BuildKeyWithAlpha(CipherDomain, tid, alpha))
}

func (p *OwnershipManagement) ReadCommit(tid string, alpha bool) ([]byte, error) {
	return p.ReadState(p.BuildKeyWithAlpha(CommitDomain, tid, alpha))
}

func (p *OwnershipManagement) WriteCommit(tid string, alpha bool, commit []byte) error {
	return p.WriteState(p.BuildKeyWithAlpha(CommitDomain, tid, alpha), commit)
}

func (p *OwnershipManagement) readAdminPk() ([]byte, error) {
	return p.ReadPkByPid(AdminPid)
}

func (p *OwnershipManagement) writeAdminPk(pk []byte) error {
	return p.WritePkByPid(AdminPid, pk)
}

func (p *OwnershipManagement) ReadOwner(tid string) (string, error) {
	owner, err := p.ReadState(p.BuildKey(OwnerDomain, tid))
	if err != nil {
		return "", err
	}
	return string(owner), nil
}

func (p *OwnershipManagement) WriteOwner(tid string, pid string) error {
	return p.WriteState(p.BuildKey(OwnerDomain, tid), []byte(string(pid)))
}

func (p *OwnershipManagement) BytesCombine(pBytes ...[]byte) []byte {
	return bytes.Join(pBytes, []byte(""))
}

// 智能合约方法代码

// AddPid 增加一个伪ID
func (p *OwnershipManagement) AddPid() protogo.Response {
	pidBytes := p.ReadArgs("pid")
	pid := string(pidBytes)
	pk := p.ReadArgs("pk")
	rText := p.ReadArgs("r")
	sText := p.ReadArgs("s")
	content := p.BytesCombine(pidBytes, pk)
	err := p.VerifyAdmin(content, rText, sText)
	if err != nil {
		return sdk.Error("permission deny:" + err.Error())
	} else {
		err := p.WritePkByPid(pid, pk)
		if err != nil {
			return sdk.Error(err.Error())
		}
		return sdk.Success([]byte("tid add success"))
	}
}

// CreateProduct 智能合约中的方法,创建产品。
//@contract_arg tid：产品ID
//@contract_arg pid: 制造商的伪ID
//@contract_arg r: 椭圆曲线签名中的r,十进制整数文本形式
//@contract_arg s: 椭圆曲线签名中的s，十进制整数文本形式
func (p *OwnershipManagement) CreateProduct() protogo.Response {
	tid := p.ReadArgs("tid")
	pid := p.ReadArgs("pid")
	content := p.BytesCombine(tid, pid)
	rText := p.ReadArgs("r")
	sText := p.ReadArgs("s")
	err := p.VerifyAdmin(content, rText, sText)
	if err != nil {
		return sdk.Error("permission deny" + err.Error())
	}
	tidStr := string(tid)
	has := p.HasProduct(tidStr)
	if has {
		return sdk.Error("already has product")
	} else {
		err := p.WriteOwner(tidStr, string(pid))
		if err != nil {
			return sdk.Error(err.Error())
		}
		return sdk.Success([]byte("create product success"))
	}
}

func (p *OwnershipManagement) ReadCipherValueBatch() protogo.Response {
	tidByte := p.ReadArgs("tid")
	tids, err := utils.DecodeTid(tidByte)
	if err != nil {
		return sdk.Error(err.Error())
	}
	buffer := bytes.NewBuffer([]byte{})
	for _, tid := range tids {
		alphaGama, err := p.ReadCipher(tid, true)
		if err != nil {
			return sdk.Error(err.Error())
		}
		betaGama, err := p.ReadCipher(tid, false)
		if err != nil {
			return sdk.Error(err.Error())
		}
		err = binary.Write(buffer, binary.BigEndian, int32(len(alphaGama)))
		if err != nil {
			return sdk.Error(err.Error())
		}
		err = binary.Write(buffer, binary.BigEndian, alphaGama)
		if err != nil {
			return sdk.Error(err.Error())
		}
		err = binary.Write(buffer, binary.BigEndian, int32(len(betaGama)))
		if err != nil {
			return sdk.Error(err.Error())
		}
		err = binary.Write(buffer, binary.BigEndian, betaGama)
		if err != nil {
			return sdk.Error(err.Error())
		}
	}
	return sdk.Success(buffer.Bytes())
}

// UploadAlpha 智能合约中的方法,原所有者上传alpha的密文，承诺
// @contract_arg tid：标签ID
// @contract_arg gama: alpha的密文
// @contract_arg commit: alpha的承诺
// @contract_arg r: 椭圆曲线签名中的r,十进制整数文本形式
// @contract_arg s: 椭圆曲线签名中的s，十进制整数文本形式
func (p *OwnershipManagement) UploadAlpha() protogo.Response {
	tid := p.ReadArgs("tid")
	gama := p.ReadArgs("gama")
	commit := p.ReadArgs("commit")
	rText := p.ReadArgs("r")
	sText := p.ReadArgs("s")
	owner, err := p.ReadOwner(string(tid))
	if err != nil {
		return sdk.Error(err.Error())
	}
	err = p.VerifyPid(owner, p.BytesCombine(tid, gama, commit), rText, sText)
	if err != nil {
		return sdk.Error(err.Error())
	}
	err = p.WriteCipher(string(tid), true, gama)
	if err != nil {
		return sdk.Error(err.Error())
	}
	err = p.WriteCommit(string(tid), true, commit)
	if err != nil {
		return sdk.Error(err.Error())
	}
	return sdk.Success([]byte("upload alpha success"))
}

// UploadBeta 智能合约中的方法,管理员上传Beta的密文，承诺
// @contract_arg tid：标签ID
// @contract_arg gama: alpha的密文
// @contract_arg commit: alpha的承诺
// @contract_arg r: 椭圆曲线签名中的r,十进制整数文本形式
// @contract_arg s: 椭圆曲线签名中的s，十进制整数文本形式
func (p *OwnershipManagement) UploadBeta() protogo.Response {
	tid := p.ReadArgs("tid")
	gama := p.ReadArgs("gama")
	commit := p.ReadArgs("commit")
	rText := p.ReadArgs("r")
	sText := p.ReadArgs("s")
	err := p.VerifyAdmin(p.BytesCombine(tid, gama, commit), rText, sText)
	if err != nil {
		return sdk.Error(err.Error())
	}
	err = p.WriteCipher(string(tid), false, gama)
	if err != nil {
		return sdk.Error(err.Error())
	}
	err = p.WriteCommit(string(tid), false, commit)
	if err != nil {
		return sdk.Error(err.Error())
	}
	return sdk.Success([]byte("upload Beta success"))
}

func (p *OwnershipManagement) ReadCipherValue() protogo.Response {
	tid := p.ReadArgs("tid")
	alphaGama, err := p.ReadCipher(string(tid), true)
	if err != nil {
		return sdk.Error(err.Error())
	}
	betaGama, err := p.ReadCipher(string(tid), false)
	if err != nil {
		return sdk.Error(err.Error())
	}
	buffer := bytes.NewBuffer([]byte{})

	err = binary.Write(buffer, binary.BigEndian, int32(len(alphaGama)))
	if err != nil {
		return sdk.Error(err.Error())
	}
	err = binary.Write(buffer, binary.BigEndian, alphaGama)
	if err != nil {
		return sdk.Error(err.Error())
	}
	err = binary.Write(buffer, binary.BigEndian, int32(len(betaGama)))
	if err != nil {
		return sdk.Error(err.Error())
	}
	err = binary.Write(buffer, binary.BigEndian, betaGama)
	if err != nil {
		return sdk.Error(err.Error())
	}
	return sdk.Success(buffer.Bytes())
}

//BatchTransfer 智能合约中的方法,批量转移产品。
//@contract_arg tid：伪ID
//@contract_arg pid：新所有者
//@contract_arg pSecret:聚合的秘密值
//@contract_arg opening:聚合的盲因子
//@contract_arg r: 椭圆曲线签名中的r,十进制整数文本形式
//@contract_arg s: 椭圆曲线签名中的s，十进制整数文本形式
func (p *OwnershipManagement) BatchTransfer() protogo.Response {
	allTids := p.ReadArgs("tid")
	pid := p.ReadArgs("pid")
	pSecret := p.ReadArgs("pSecret")
	opening := p.ReadArgs("opening")
	content := p.BytesCombine(pid, allTids, pSecret, opening)
	rText := p.ReadArgs("r")
	sText := p.ReadArgs("s")
	err := p.VerifyPid(string(pid), content, rText, sText)
	if err != nil {
		return sdk.Error(err.Error())
	}

	tidList, err := utils.DecodeTid(allTids)
	if err != nil {
		return sdk.Error(err.Error())
	}
	length := len(tidList)
	openings := make([]byte, 32)
	commits, err := bulletproofs.PedersenCommitSpecificOpening(0, openings)
	if err != nil {
		return sdk.Error(err.Error())
	}
	for i := 0; i < length; i++ {
		tid := tidList[i]
		commitAlpha, err := p.ReadCommit(tid, true)
		if err != nil {
			return sdk.Error(err.Error())
		}
		commitBeta, err := p.ReadCommit(tid, false)
		if err != nil {
			return sdk.Error(err.Error())
		}
		tempCommitAd, err := bulletproofs.PedersenAddCommitment(commitAlpha, commitBeta)
		if err != nil {
			return sdk.Error(err.Error())
		}
		tempCommit, err := bulletproofs.PedersenAddCommitment(tempCommitAd, commits)
		if err != nil {
			return sdk.Error(err.Error())
		}
		commits = tempCommit
	}
	u := utils.BytesToUint64(pSecret)
	addOpening, err := bulletproofs.PedersenAddOpening(opening, openings)
	if err != nil {
		return sdk.Error(err.Error())
	}
	res, _ := bulletproofs.PedersenVerify(commits, addOpening, u)
	if !res {
		sdk.Error("permission deny when batch transfer product:commit not match")
	}
	for i := 0; i < length; i++ {
		tid := tidList[i]
		err := p.WriteOwner(tid, string(pid))
		if err != nil {
			return sdk.Error(err.Error())
		}
	}
	return sdk.Success([]byte("transfer product success"))
}

func (p *OwnershipManagement) HasProduct(tid string) bool {
	return p.HasState(p.BuildKey(OwnerDomain, tid))
}

func (p *OwnershipManagement) ReadFailReason() protogo.Response {
	val, _ := p.ReadState("fail_reason")
	return sdk.Success(val)
}

func (p *OwnershipManagement) VerifyAdmin(content, rText, sText []byte) error {
	pkBytes, err := p.readAdminPk()
	if err != nil {
		return err
	}
	return ecdsa_pid.VerifySign(pkBytes, content, rText, sText)
}

func (p *OwnershipManagement) VerifyPid(pid string, content, rText, sText []byte) error {
	pkBytes, err := p.ReadPkByPid(pid)
	if err != nil {
		return err
	}
	return ecdsa_pid.VerifySign(pkBytes, content, rText, sText)
}

func main() {
	err := sandbox.Start(new(OwnershipManagement))
	if err != nil {
		log.Fatal(err)
	}
}
