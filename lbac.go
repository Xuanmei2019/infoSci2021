/*
 * Copyright (c) 2018 XLAB d.o.o
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package main

import (
    "fmt"
    "bytes"
    "encoding/json"
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/bn256"
	"math/big"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	sc "github.com/hyperledger/fabric/protos/peer"
	
)
type SmartContract struct {
}

type AttributesTable struct{
	Attributes []int
	Period []int
	K0 []byte
	K []byte
	KPrime []byte
	AttribToI []byte
}

type CipherKeyTable struct{
	Ct0 []byte
	Ct []byte
	CtPrime []byte
	Msp []byte
}

type MidResult struct{
	TkPairing  []byte
}

var lbac = abe.NewLBAC()
var debug = true
var sep = []byte("  ")
var index = 0
// Main
func main() {
	err := shim.Start(new(SmartContract))
	if err != nil {
		fmt.Printf("Error starting abe chaincode: %s", err)
	}
}




/*
 * The Init method is called when the Smart Contract "fabcar" is instantiated by the blockchain network
 * Best practice is to have any Ledger initialization in separate function -- see initLedger()
 */
func (s *SmartContract) Init(APIstub shim.ChaincodeStubInterface) sc.Response {
	return shim.Success(nil)
}

/*
 * The Invoke method is called as a result of an application request to run the Smart Contract "fabcar"
 * The calling application program has also specified the particular smart contract function to be called, with arguments
 */
func (s *SmartContract) Invoke(APIstub shim.ChaincodeStubInterface) sc.Response {

	// Retrieve the requested Smart Contract function and arguments
	function, args := APIstub.GetFunctionAndParameters()
	// Route to the appropriate handler function to interact with the ledger appropriately
	if function == "initLedger" {
		return s.initLedger(APIstub)
	} else if function == "GenerateMasterKeys" {
		return s.GenerateMasterKeys(APIstub)
	} else if function == "Encryption" {
		return s.Encryption(APIstub, args)
	}else if function == "GenerateAttribKeys" {
		return s.GenerateAttribKeys(APIstub, args)
	}else if function == "PreDecryption" {
		return s.PreDecryption(APIstub,args)
	}else if function == "Decryption" {
		return s.Decryption(APIstub,args)
	
	}else if function == "SetPubKeyTx" {
		return s.SetPubKeyTx(APIstub)
	}else if function == "GetPubKeyTx" {
		return s.GetPubKeyTx(APIstub)
	}else if function == "SetUAKTx" {
		return s.SetUAKTx(APIstub, args)
	}else if function == "UploadCtTx" {
		return s.UploadCtTx(APIstub, args)
	} 

	return shim.Error("Invalid Smart Contract function name.")
}


func (s *SmartContract) initLedger(APIstub shim.ChaincodeStubInterface) sc.Response {

	fmt.Println("===================initLedger========================\n")
	// define a set of attributes (a subset of the universe of attributes)
	// that an entity possesses
	gamma := []int{0, 2, 3, 5}
	fmt.Println("attributes =>")
	fmt.Println(gamma)
	// create a new lbac struct with the universe of attributes
	// denoted by integer
	/*
	a := abe.NewLBAC()
	objectAsBytes, err := json.Marshal (&a) //对象a
 	err = APIstub.PutState("object_a", objectAsBytes)
 	if err != nil {
        fmt.Println("Could not PutState(object_a)!", err)
        return shim.Error(err.Error())
 	}*/
	return shim.Success(nil)
}



func (s *SmartContract) GenerateMasterKeys(APIstub shim.ChaincodeStubInterface) sc.Response {
/*
	startKey := "USERATT0"
	//endKey := "USERATT999"
	piBytes, err := APIstub.GetState(startKey) 
	var user UserAtt 
	err = json.Unmarshal(piBytes, &user)
 	fmt.Println(user)
	return shim.Success(piBytes)
	*/
	fmt.Println("===================GenerateMasterKeys========================\n")
	/*
	aBytes, err := APIstub.GetState("object_a") 
	var lbac *abe.LBAC 

	err = json.Unmarshal(aBytes, &lbac)
	*/
	//------------------------------------------------------------------
	pubKey, secKey, err := lbac.GenerateMasterKeys()
	if err != nil {
        fmt.Println("Error generate Master keys!", err)
 	    return shim.Error(err.Error())
 	}
 
 	if debug {
	 	fmt.Printf("pubKey:  %+v\n ",pubKey)
	 	fmt.Printf("secKey:  %+v\n ",secKey)
 	}
 	//------------------------------------------------------------------

	pkG2Asbyte := make([][]byte, 256/8*3)
	pkGTAsbyte := make([][]byte, 256/8*3)
	for i:=0; i<2; i++ {
		pkG2Asbyte[i] = pubKey.PartG2[i].Marshal()
		pkGTAsbyte[i] = pubKey.PartGT[i].Marshal()
	}

	APIstub.PutState("pkG2", bytes.Join(pkG2Asbyte, sep)) //joint 转 [][]byte 为[]byte
	APIstub.PutState("pkGT", bytes.Join(pkGTAsbyte, sep))  	
	

	skIntAsBytes, _ := json.Marshal(secKey.PartInt)
	skG1Asbyte := make([][]byte, 256/8*2) //(x,y)
	for i:=0; i<3; i++ {
		skG1Asbyte[i] = secKey.PartG1[i].Marshal()
	}
	APIstub.PutState("skInt", skIntAsBytes) //joint 转 [][]byte 为[]byte
	APIstub.PutState("skG1", bytes.Join(skG1Asbyte, sep))  	

	//fmt.Printf("- struct to byte:===>g  \n%+v\n ",pubKey.PartG2[0])
	//fmt.Printf("- byte to struct:===>ug  %+v\n ",ug)

	return shim.Success(nil)

}

func (s *SmartContract) Encryption(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	fmt.Println("===================Encryption========================\n")
	if len(args) != 3 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}
	/*
	aBytes, err := APIstub.GetState("object_a") 
	var lbac *abe.LBAC 
	err = json.Unmarshal(aBytes, &lbac)
	fmt.Println("lbac==>")
 	fmt.Printf("%+v\n",lbac)
	*/

	pkG2Byte, err := APIstub.GetState("pkG2") 
	pkGTByte, err := APIstub.GetState("pkGT") 

	pkG2Asbyte := bytes.Split(pkG2Byte, sep) //split转 []byte 为[][]byte
	pkGTAsbyte := bytes.Split(pkGTByte, sep) 

	var pkG2 [2]*bn256.G2
	var pkGT [2]*bn256.GT
	for i:=0; i<2; i++ {
		pkG2[i], _ = new(bn256.G2).Unmarshal(pkG2Asbyte[i])
		pkGT[i], _ = new(bn256.GT).Unmarshal(pkGTAsbyte[i])		
	}

 	pubKey := &abe.LBACPubKey{PartG2: pkG2, PartGT: pkGT}
 	/*fmt.Println("pubKey==>")
 	fmt.Printf("%+v\n", pubKey)*/
 	//------------------------------------------------------------------
    //-*加密部分可由owner链下完成*-
	//msg := "Attack at dawn!"
	msg := args[0]
	fmt.Println("msg =>")
	fmt.Println(msg)
	
	//policy := "((0 AND 1) OR (2 AND 3)) AND 5"	
	policy := args[1]
	fmt.Println("policy =>")
	fmt.Println(policy)
 	msp, err:= abe.BooleanToMSP(policy, false)	

 	if err != nil {
        fmt.Println("BooleanToMSP Error! ", err)
        return shim.Error(err.Error())
 	}

	cipher, _ := lbac.Encrypt(msg, msp, pubKey)
	if debug {
		fmt.Println("Ciphertext=>")
	 	fmt.Printf("%+v\n", cipher)
	 }
    //------------------------------------------------------------------
    //ct0 to byte
    ct0Asbyte := make([][]byte, 256/8*3)
    for i:=0; i<3; i++ {
		ct0Asbyte[i] = cipher.Ct0[i].Marshal()		
	}
	APIstub.PutState("ct0", bytes.Join(ct0Asbyte,sep))

    //ct to byte

	ctAsByte := make([][]byte, len(msp.Mat)*3)
	n := 0
	for i := 0; i < len(msp.Mat); i++ {
		for l := 0; l<3; l++ {
			//fmt.Printf("%+v\n", cipher.Ct[i][l])
			ctAsByte[n] = cipher.Ct[i][l].Marshal()					
			n++	
		}
	}
	//APIstub.PutState("ct", bytes.Join(ctAsByte,sep))
	// //ctprime to byte
	ctPrimeAsbyte := cipher.CtPrime.Marshal()
	//APIstub.PutState("ctPrime", ctPrimeAsbyte)
	//MSP to byte
	mspAsBytes, _ := json.Marshal(cipher.Msp)
	//APIstub.PutState("msp", mspAsBytes)

	var cipherKeyTable = CipherKeyTable{}
	cipherKeyTable.Ct0 = bytes.Join(ct0Asbyte,sep)
	cipherKeyTable.Ct = bytes.Join(ctAsByte,sep)
	cipherKeyTable.CtPrime = ctPrimeAsbyte
	cipherKeyTable.Msp = mspAsBytes
	//fmt.Println("cipherKeyTable=>")
 	//fmt.Printf("%+v\n", cipherKeyTable)
	cipherKeyTableAsBytes,_ :=json.Marshal(cipherKeyTable)
	APIstub.PutState(args[2],cipherKeyTableAsBytes)

	return shim.Success(cipherKeyTableAsBytes)
}


func (s *SmartContract) GenerateAttribKeys(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	fmt.Println("===================GenerateAttribKeys========================\n")
	//gamma := []int{0, 2, 3, 5}
	/*
	aBytes, err := APIstub.GetState("object_a") 
	var lbac *abe.LBAC 
	err = json.Unmarshal(aBytes, &lbac)
	fmt.Println("lbac==>")
 	fmt.Printf("%+v\n",lbac)
	*/
	//returns the marshaled serialized identity of the Client
	//serializedIDByte,_ := APIstub.GetCreator()
	//serializedIDStr := string(serializedIDByte)
	skIntAsBytes, err := APIstub.GetState("skInt") 
	skG1Byte, err := APIstub.GetState("skG1") 
	skG1Asbyte := bytes.Split(skG1Byte, sep) 
	// byte to sk
	var skInt [4]*big.Int
	json.Unmarshal(skIntAsBytes, &skInt)
	var skG1 [3]*bn256.G1
	for i:=0; i<3; i++ {
		skG1[i], _ = new(bn256.G1).Unmarshal(skG1Asbyte[i])		
	}
	secKey := &abe.LBACSecKey{PartInt: skInt, PartG1: skG1}
	fmt.Printf("secKey ==> %+v\n",secKey)
	//------------------------------------------------------------------

	// string to []int
	var gamma []int
	json.Unmarshal([]byte(args[1]), &gamma)
	fmt.Printf("Attributes ==> %#v\n",gamma)
	var period []int
	json.Unmarshal([]byte(args[2]), &period)
	fmt.Printf("Period ==> %#vs\n",period)

	keys, _:= lbac.GenerateAttribKeys(gamma, secKey)
 	//fmt.Printf("%+v\n",keys)
 	if err != nil {
        fmt.Println("GenerateAttribKeys Error! ", err)
        return shim.Error(err.Error())
 	}
 	//------------------------------------------------------------------
 	//k0 to byte
 	k0Asbyte := make([][]byte, 256/8*3) 
    for i:=0; i<3; i++ {
		k0Asbyte[i] = keys.K0[i].Marshal()		
	}
	//APIstub.PutState("k0", bytes.Join(k0Asbyte,sep))

    //K to byte
	kAsByte := make([][]byte, len(gamma)*3)
	n := 0
	for i := 0; i < len(gamma); i++ {
		for l := 0; l<3; l++ {
			//fmt.Printf("%+v\n", cipher.Ct[i][l])
			kAsByte[n] = keys.K[i][l].Marshal()					
			n++	
		}
	}
	//APIstub.PutState("k", bytes.Join(kAsByte,sep))
	//kPrime to byte
	kPrimeAsbyte := make([][]byte, 256/8*3) 
    for i:=0; i<3; i++ {
		kPrimeAsbyte[i] = keys.KPrime[i].Marshal()		
	}
	//APIstub.PutState("kPrime", bytes.Join(kPrimeAsbyte,sep))
	//AttribToI to byte
	AToIAsbyte, _ :=json.Marshal(keys.AttribToI)
	//APIstub.PutState("attribToI", AToIAsbyte)

	var attributesTable = AttributesTable{}
	attributesTable.Attributes = gamma
	attributesTable.Period = period
	attributesTable.K0 = bytes.Join(k0Asbyte,sep)
	attributesTable.K = bytes.Join(kAsByte,sep)
	attributesTable.KPrime = bytes.Join(kPrimeAsbyte,sep)
	attributesTable.AttribToI = AToIAsbyte
	//fmt.Println("attributesTable=>")
 	//fmt.Printf("%+v\n", attributesTable)
	attributesTableAsBytes,_ :=json.Marshal(attributesTable)
	APIstub.PutState(args[0],attributesTableAsBytes)

	return shim.Success(attributesTableAsBytes)
}



func (s *SmartContract) PreDecryption(APIstub shim.ChaincodeStubInterface,args []string) sc.Response {
	fmt.Println("===================PreDecryption========================\n")
	/*
	aBytes, _ := APIstub.GetState("object_a") 
	var lbac *abe.LBAC 
	err := json.Unmarshal(aBytes, &lbac)
	fmt.Println("lbac==>")
 	fmt.Printf("%+v\n",lbac)
	*/
 	/*ct0Byte, err := APIstub.GetState("ct0") 
	ctByte, err := APIstub.GetState("ct") 
 	ctPrimeAsBytes, err := APIstub.GetState("ctPrime") 
	mspAsBytes, err := APIstub.GetState("msp") 
	*/
	//------checking policy by dataHash/Index-----
	cipherKeyTableAsBytes,_:= APIstub.GetState(args[0])
 	cipherKeyTable := CipherKeyTable{}
 	json.Unmarshal(cipherKeyTableAsBytes,&cipherKeyTable)
	//fmt.Println("==>cipherKeyTable")
 	//fmt.Printf("%+v\n",cipherKeyTable)
	ct0Byte := cipherKeyTable.Ct0
	ctByte := cipherKeyTable.Ct
	ctPrimeAsBytes := cipherKeyTable.CtPrime
	mspAsBytes := cipherKeyTable.Msp
	ct0Asbyte := bytes.Split(ct0Byte, sep) 
	ctAsbyte := bytes.Split(ctByte, sep) 
	//byte to ct0
	var ct0 [3]*bn256.G2
	for i:=0; i<3; i++ {
		ct0[i], _ = new(bn256.G2).Unmarshal(ct0Asbyte[i])		
	}
	//byte to msp
	var m *abe.MSP
	json.Unmarshal(mspAsBytes, &m)	
	//byte to ct
	ct := make([][3]*bn256.G1, len(m.Mat))
	for i:= 0; i< len(m.Mat)*3; i++{	
		ct[i/3][i%3], _ = new(bn256.G1).Unmarshal(ctAsbyte[i])
	}
	//byte to ctPrime
	var ctPrime *bn256.GT
	ctPrime, _ = new(bn256.GT).Unmarshal(ctPrimeAsBytes)

 	cipher := &abe.LBACCipher{Ct0: ct0, Ct: ct, CtPrime: ctPrime, Msp: m}
	//------------------------------------------------------------------
 	/*k0Byte, err := APIstub.GetState("k0") 
	kByte, err := APIstub.GetState("k") 
 	kPrimeByte, err := APIstub.GetState("kPrime") 
	attribToIAsByte, err := APIstub.GetState("attribToI")
	*/
	//------checking attributes by userID-----
	attributesTableAsBytes,_:= APIstub.GetState(args[1])
 	attributesTable := AttributesTable{}
 	json.Unmarshal(attributesTableAsBytes,&attributesTable)
	//fmt.Println("==>attributesTable")
 	//fmt.Printf("%+v\n",attributesTable)	
 	//period := attributesTable.Period
	k0Byte := attributesTable.K0
	kByte := attributesTable.K
	kPrimeByte := attributesTable.KPrime
	attribToIAsByte := attributesTable.AttribToI

	k0Asbyte := bytes.Split(k0Byte, sep) 
	kAsbyte := bytes.Split(kByte, sep) 
	kPrimeAsbyte := bytes.Split(kPrimeByte, sep)
 	//byte to k0
	var k0 [3]*bn256.G2
	for i:=0; i<3; i++ {
		k0[i], _ = new(bn256.G2).Unmarshal(k0Asbyte[i])		
	}
	//byte to attribToI
	var attribToI map[int]int
	json.Unmarshal(attribToIAsByte, &attribToI)
	//byte to k
	attribMap := make(map[int]bool)
	for k := range attribToI {
		attribMap[k] = true
	}
	countAttr := 0
	for i := 0; i < len(cipher.Msp.Mat); i++ {
		if attribMap[cipher.Msp.RowToAttrib[i]] {
			countAttr += 1
		}
	}
	k := make([][3]*bn256.G1, countAttr)
	for i:= 0; i< countAttr*3; i++{	
		k[i/3][i%3], _ = new(bn256.G1).Unmarshal(kAsbyte[i])
	}
	//byte to kPrime
	var kPrime [3]*bn256.G1
	for i:=0; i<3; i++ {
		kPrime[i], _ = new(bn256.G1).Unmarshal(kPrimeAsbyte[i])		
	}


	keys := &abe.LBACAttribKeys{K0: k0, K: k, KPrime: kPrime, AttribToI: attribToI}

	//------------------------------------------------------------------
	pkG2Byte, err := APIstub.GetState("pkG2") 
	pkGTByte, err := APIstub.GetState("pkGT") 

	pkG2Asbyte := bytes.Split(pkG2Byte, sep) //split转 []byte 为[][]byte
	pkGTAsbyte := bytes.Split(pkGTByte, sep) 

	var pkG2 [2]*bn256.G2
	var pkGT [2]*bn256.GT
	for i:=0; i<2; i++ {
		pkG2[i], _ = new(bn256.G2).Unmarshal(pkG2Asbyte[i])
		pkGT[i], _ = new(bn256.GT).Unmarshal(pkGTAsbyte[i])		
	}

 	pubKey := &abe.LBACPubKey{PartG2: pkG2, PartGT: pkGT}
 	//------------------------------------------------------------------

	token, err := lbac.PreDecrypt(cipher, keys, pubKey)

	if err != nil {
        fmt.Println("PreDecrypt Error! ", err)
        return shim.Error(err.Error())
 	}
	fmt.Println("midcipher==> ", token)
	//token as byte
	tokenAsbyte := make([][]byte, 256/8*3) 
    for i:=0; i<3; i++ {
		tokenAsbyte[i] = token.TkPairing[i].Marshal()		
	}
	var midResult = MidResult{}
	midResult.TkPairing = bytes.Join(tokenAsbyte,sep)
	midResultAsBytes,_ :=json.Marshal(midResult)
	tmpString :=  args[0]+args[1] //arg[0]: userId, arg[1]:dataHash
	APIstub.PutState(tmpString, midResultAsBytes) 
	return shim.Success(midResultAsBytes)

}

func (s *SmartContract) Decryption(APIstub shim.ChaincodeStubInterface,args []string) sc.Response {
	fmt.Println("===================Decryption========================\n")
	tmpString :=  args[0]+args[1] //arg[0]: userId, arg[1]:dataHash
	midResultAsBytes,_:= APIstub.GetState(tmpString)
 	midResult := MidResult{}
 	json.Unmarshal(midResultAsBytes,&midResult)

 	tkPairingByte := midResult.TkPairing
 	tkPairingAsbyte := bytes.Split(tkPairingByte, sep)
 	
	var tk [3]*bn256.GT

	for i:=0; i<3; i++ {
		tk[i], _ = new(bn256.GT).Unmarshal(tkPairingAsbyte[i])
		
	}
	token := &abe.LBACMidResult{TkPairing:tk }



	cipherKeyTableAsBytes,_:= APIstub.GetState(args[0])
 	cipherKeyTable := CipherKeyTable{}
 	json.Unmarshal(cipherKeyTableAsBytes,&cipherKeyTable)
	//fmt.Println("==>cipherKeyTable")
 	//fmt.Printf("%+v\n",cipherKeyTable)
	ct0Byte := cipherKeyTable.Ct0
	ctByte := cipherKeyTable.Ct
	ctPrimeAsBytes := cipherKeyTable.CtPrime
	mspAsBytes := cipherKeyTable.Msp
	ct0Asbyte := bytes.Split(ct0Byte, sep) 
	ctAsbyte := bytes.Split(ctByte, sep) 
	//byte to ct0
	var ct0 [3]*bn256.G2
	for i:=0; i<3; i++ {
		ct0[i], _ = new(bn256.G2).Unmarshal(ct0Asbyte[i])		
	}
	//byte to msp
	var m *abe.MSP
	json.Unmarshal(mspAsBytes, &m)	
	//byte to ct
	ct := make([][3]*bn256.G1, len(m.Mat))
	for i:= 0; i< len(m.Mat)*3; i++{	
		ct[i/3][i%3], _ = new(bn256.G1).Unmarshal(ctAsbyte[i])
	}
	//byte to ctPrime
	var ctPrime *bn256.GT
	ctPrime, _ = new(bn256.GT).Unmarshal(ctPrimeAsBytes)

 	cipher := &abe.LBACCipher{Ct0: ct0, Ct: ct, CtPrime: ctPrime, Msp: m}

	msgCheck, _:= lbac.Decrypt(cipher, token)
	//msg := "Attack at dawn!"
	

    return shim.Success([]byte(msgCheck))
}

func (s *SmartContract) SetPubKeyTx(APIstub shim.ChaincodeStubInterface) sc.Response {
	fmt.Println("===================SetPubKeyTx========================\n")

	pkG2Byte, err := APIstub.GetState("pkG2") 
	pkGTByte, err := APIstub.GetState("pkGT") 
	if err != nil {
        fmt.Println("Could not InitPubKey!", err)
        return shim.Error(err.Error())
 	}
	APIstub.PutState("pkG2v1", pkG2Byte) //joint 转 [][]byte 为[]byte
	APIstub.PutState("pkGTv1", pkGTByte)  	
	return shim.Success(nil)

}
func (s *SmartContract) GetPubKeyTx(APIstub shim.ChaincodeStubInterface) sc.Response {
	fmt.Println("===================GetPubKeyTx========================\n")

	pkG2Byte, err := APIstub.GetState("pkG2") 
	pkGTByte, err := APIstub.GetState("pkGT") 
	if err != nil {
        fmt.Println("Could not InitPubKey!", err)
        return shim.Error(err.Error())
 	}
	fmt.Println("pkG2Byte:= ", pkG2Byte)
	fmt.Println("pkGTByte:= ", pkGTByte)
	return shim.Success(nil)
}
func (s *SmartContract) UploadCtTx(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	fmt.Println("===================UploadCtTx========================\n")
	
	cipherKeyTableAsBytes,err:= APIstub.GetState(args[0])
	if err != nil {
        fmt.Println("Could not UploadCtTx!", err)
        return shim.Error(err.Error())
 	}

	APIstub.PutState(args[0]+"IndStr",cipherKeyTableAsBytes)
	return shim.Success(nil)

}
func (s *SmartContract) SetUAKTx(APIstub shim.ChaincodeStubInterface, args []string) sc.Response {
	fmt.Println("===================SetUAKTx========================\n")

	attributesTableAsBytes,err:= APIstub.GetState(args[0])
	if err != nil {
        fmt.Println("Could not SetUAKTx!", err)
        return shim.Error(err.Error())
 	}
	APIstub.PutState(args[0]+"IndStr",attributesTableAsBytes)
	return shim.Success(nil)
}
