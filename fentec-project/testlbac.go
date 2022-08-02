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
	"github.com/fentec-project/gofe/abe"
	"github.com/fentec-project/bn256"
	"encoding/json"
	"math/big"
	//"bytes"
)

func main() {
	// create a message to be encrypted
	msg := "Attack at dawn!"
	fmt.Println("msg =>")
	fmt.Println(msg)

	policy := "((0 AND 1) OR (2 AND 3)) AND 5"
	fmt.Println("policy =>")
	fmt.Println(policy)

	// define a set of attributes (a subset of the universe of attributes)
	// that an entity possesses
	gamma := []int{0, 2, 3,5}

	// create a new LBAC struct with the universe of attributes
	// denoted by integer
	a := abe.NewLBAC()

	// generate a public key and a secret key for the scheme
	pubKey, secKey, _ := a.GenerateMasterKeys()
	//fmt.Printf("pubKey:  %+v\n ",pubKey)
	fmt.Printf("secKey:  %+v\n ",secKey)
	// create a msp struct out of a boolean expression representing the
	// policy specifying which attributes are needed to decrypt the ciphertext;
	// note that safety of the encryption is only proved if the mapping
	// msp.RowToAttrib from the rows of msp.Mat to attributes is injective, i.e.
	// only boolean expressions in which each attribute appears at most once
	// are allowed - if expressions with multiple appearances of an attribute
	// are needed, then this attribute can be split into more sub-attributes

	///*****************************************************
	/*form := pubKey.PartG2[0].Marshal()
	ug,_:= new(bn256.G2).Unmarshal(form)*/

	//G2 to byte
	pkG2Asbyte := make([][]byte, 256/8*3) //(x,y,z)
	pkGTAsbyte := make([][]byte, 256/8*3)
	for i:=0; i<2; i++ {
		pkG2Asbyte[i] = pubKey.PartG2[i].Marshal()
		pkGTAsbyte[i] = pubKey.PartGT[i].Marshal()
	}

	//byte to G2
	pkG2 := make([]*bn256.G2,2)
	pkGT := make([]*bn256.GT,2)
	for i:=0; i<2; i++ {
		pkG2[i], _ = new(bn256.G2).Unmarshal(pkG2Asbyte[i])
		pkGT[i], _ = new(bn256.GT).Unmarshal(pkGTAsbyte[i])		
	}


	//fmt.Printf("pubKey:===>g  %+v\n ",pubKey.PartG2)
	//fmt.Printf("pubKey:===>ug  %+v\n ",pkG2)

	//Int to byte
	skIntAsBytes, _ := json.Marshal(secKey.PartInt)
	//G1 to byte
	skG1Asbyte := make([][]byte, 256/8*2) //(x,y)
	for i:=0; i<3; i++ {
		skG1Asbyte[i] = secKey.PartG1[i].Marshal()
	}

	//byte to int
	var skInt [4]*big.Int
	json.Unmarshal(skIntAsBytes, &skInt)
	//byte to G1
	skG1 := make([]*bn256.G1,3)
	for i:=0; i<3; i++ {
		skG1[i], _ = new(bn256.G1).Unmarshal(skG1Asbyte[i])		
	}
	fmt.Printf("secKey:===>Int  %+v\n ",skInt)
	fmt.Printf("secKey:===>  %+v\n ",skG1)


   //******************************************************//


	msp, _:= abe.BooleanToMSP(policy, false)

	// encrypt the message msg with the decryption policy specified by the
	// msp structure
	cipher, _ := a.Encrypt(msg, msp, pubKey)

	fmt.Println("Ciphertext...")
  	fmt.Printf("pubKey:===>g  %+v\n ", cipher.Msp)


   ///*******************************************************
	//[][3]*bn256.G1 ct to byte
	s := make([][]byte, len(msp.Mat)*3)
	n := 0
	for i := 0; i < len(msp.Mat); i++ {
		for l := 0; l<3; l++ {
			//fmt.Printf("%+v\n", cipher.Ct[i][l])
			s[n] = cipher.Ct[i][l].Marshal()					
			n++	
		}
	}
	//byte to ct [][3]*bn256.G1
	c := make([][3]*bn256.G1, len(msp.Mat))
	for i:= 0; i< len(msp.Mat)*3; i++{	
		c[i/3][i%3], _ = new(bn256.G1).Unmarshal(s[i])
		//fmt.Printf("Unmarshal ==> %+v\n", c[i/3][i%3])

	}

	//msp to byte
	mspAsBytes, _ := json.Marshal(cipher.Msp)
	var m abe.MSP
	json.Unmarshal(mspAsBytes, &m)
	fmt.Printf("Unmarshal:MSP==>,%+v\n ", m)
   //*******************************************************//








	// generate keys for decryption for an entity with
	// attributes gamma
	keys, _:= a.GenerateAttribKeys(gamma, secKey)

	fmt.Println("sk :=>")
	fmt.Println(keys)	
	///*******************************************************
 	k0Asbyte := make([][]byte, 256/8*3) 
    for i:=0; i<3; i++ {
		k0Asbyte[i] = keys.K0[i].Marshal()		
	}

    //K to byte
    fmt.Printf("k==>,%+v\n ", keys.K)
	kAsByte := make([][]byte, len(gamma)*3)
	n = 0
	for i := 0; i < len(gamma); i++ {
		for l := 0; l<3; l++ {
			//fmt.Printf("%+v\n", cipher.Ct[i][l])
			kAsByte[n] = keys.K[i][l].Marshal()					
			n++	
		}
	}
	 fmt.Printf("len==>,\n%d\n %d", len(gamma),len(m.Mat))
	//byte to k
	attribMap := make(map[int]bool)
	for k := range keys.AttribToI {
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
		k[i/3][i%3], _ = new(bn256.G1).Unmarshal(kAsByte[i])
	}
	fmt.Printf("Unmarshal:k==>,%+v\n ", k)
	//kPrime to byte
	kPrimeAsbyte := make([][]byte, 256/8*3) 
    for i:=0; i<3; i++ {
		kPrimeAsbyte[i] = keys.KPrime[i].Marshal()		
	}

	//AttribToI to byte
	AToIAsbyte, _ :=json.Marshal(keys.AttribToI)
	var attribToI map[int]int
	json.Unmarshal(AToIAsbyte, &attribToI)
	fmt.Printf("Unmarshal:AToIAsbyte==>,%+v\n ", attribToI)



	//*******************************************************//




	// decrypt the ciphertext with the keys of an entity
	// that has sufficient attributes
	msgCheck, _ := a.Decrypt(cipher, keys, pubKey)
	
	fmt.Println("Decrypt...")
	fmt.Println(msgCheck)
    if msg == msgCheck { 
    	fmt.Println("Successful Decryption!!!")
    }else{
		fmt.Println("Decryption. Failed!!!")
    	}

}
