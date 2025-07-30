#include <cstdint>
#include <iostream>
#include "openfhe.h"
#include <stdlib.h>

using namespace lbcrypto;

int main() {
    uint32_t plaintextModules = 2;
    uint32_t numHops = 13;

    CCParams<CryptoContextBGVRNS> params;
    params.SetPlaintextModulus(plaintextModules);
    params.SetScalingTechnique(FIXEDMANUAL);
    params.SetPRENumHops(numHops);
    params.SetStatisticalSecurity(40);
    params.SetNumAdversarialQueries(1048576);
    params.SetRingDim(32768);
    params.SetPREMode(NOISE_FLOODING_HRA);
    params.SetKeySwitchTechnique(HYBRID);
    params.SetMultiplicativeDepth(0);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(PRE);
    // cryptoContext->Enable(ADVANCEDSHE);

    ////////////////////////////////////////////////////////////
    // PRINT PARAMS
    ////////////////////////////////////////////////////////////
    std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2
              << std::endl;
    std::cout << "log2 q = "
              << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;
    const auto cryptoParamsBGV = std::dynamic_pointer_cast<CryptoContextBGVRNS>(cc->GetCryptoParameters());
    // std::cout << "log QP = " << cryptoParamsBGV->GetParamsQP()->GetModulus().GetMSB() << std::endl;
    auto ringsize = cc->GetRingDimension();
    std::cout << "You can encrypt " << ringsize / 8 << "bytes of data" << std::endl;

    ////////////////////////////////////////////////////////////
    // Perform Key Generation Operation
    ////////////////////////////////////////////////////////////
    KeyPair<DCRTPoly> keyPair1;
    keyPair1 = cc->KeyGen();

    if (!keyPair1.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }

    ////////////////////////////////////////////////////////////
    // Plaintext encoding
    ////////////////////////////////////////////////////////////
    std::string message = "Secret Hello World\n";
    std::vector<int64_t> vShorts;
    for (size_t i = 0; i < message.length(); i++) {
        char mchar = message[i];
        vShorts.push_back(((mchar >> 7) & 1) % plaintextModules);
        vShorts.push_back(((mchar >> 6) & 1) % plaintextModules);
        vShorts.push_back(((mchar >> 5) & 1) % plaintextModules);
        vShorts.push_back(((mchar >> 4) & 1) % plaintextModules);
        vShorts.push_back(((mchar >> 3) & 1) % plaintextModules);
        vShorts.push_back(((mchar >> 2) & 1) % plaintextModules);
        vShorts.push_back(((mchar >> 1) & 1) % plaintextModules);
        vShorts.push_back(((mchar >> 0) & 1) % plaintextModules);
    }
    Plaintext pt = cc->MakeCoefPackedPlaintext(vShorts);
    
    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////
    auto ct1 = cc->Encrypt(keyPair1.publicKey, pt);
    

    ////////////////////////////////////////////////////////////
    // Decryption of ciphertext
    ////////////////////////////////////////////////////////////
    Plaintext ptDec1;
    cc->Decrypt(keyPair1.secretKey, ct1, &ptDec1);
    ptDec1->SetLength(pt->GetLength());

    
    ////////////////////////////////////////////////////////////
    // Keygen Operation
    ////////////////////////////////////////////////////////////
    KeyPair<DCRTPoly> newKeyPair;
    EvalKey<DCRTPoly> reKey;

    newKeyPair = cc->KeyGen();
    if (!newKeyPair.good()) {
        std::cout << "New Key generation failed!" << std::endl;
        return (false);
    }
    reKey = cc->ReKeyGen(keyPair1.secretKey, newKeyPair.publicKey);

    ////////////////////////////////////////////////////////////
    // Re-Encryption
    ////////////////////////////////////////////////////////////
    ct1 = cc->ReEncrypt(ct1, reKey);

    ////////////////////////////////////////////////////////////
    // Decryption of Re-Encryption
    ////////////////////////////////////////////////////////////
    Plaintext ptDec2;
    cc->Decrypt(newKeyPair.secretKey, ct1, &ptDec2);
    ptDec2->SetLength(pt->GetLength());

    auto unpacked0 = pt->GetCoefPackedValue();
    auto unpacked1 = ptDec1->GetCoefPackedValue();
    auto unpacked2 = ptDec2->GetCoefPackedValue();

    for(unsigned int j=0; j< pt->GetLength(); j++) {
        if (unpacked1[j] < 0)
            unpacked1[j] += plaintextModules;
        if (unpacked2[j] < 0)
            unpacked2[j] += plaintextModules;
    }

    bool good = true;
    for (unsigned int j = 0; j < pt->GetLength(); j++) {
        if ((unpacked0[j] != unpacked1[j]) || (unpacked0[j] != unpacked2[j])) {
            good = false;
        }
    }
    if (good) {
        std::cout << "PRE passes" << std::endl;
    }
    else {
        std::cout << "PRE fails" << std::endl;
    }


    return 0;
}
