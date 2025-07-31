#include <cstdint>
#include <iostream>
#include "openfhe.h"
#include <stdlib.h>

using namespace lbcrypto;

const uint32_t plaintextModules = 2;
const uint32_t numHops = 13;

CryptoContext<DCRTPoly> init() {
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
    return cc;
}

KeyPair<DCRTPoly> genKeyPair(CryptoContext<DCRTPoly> cc) {

    KeyPair<DCRTPoly> keyPair = cc->KeyGen();

    if (!keyPair.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }
    return keyPair;
}

Plaintext encodePlainText(CryptoContext<DCRTPoly> cc, std::vector<uint8_t> data) {
    std::vector<int64_t> vShorts;
    for (size_t i = 0; i < data.size(); i++) {
        char mchar = data[i];
        vShorts.push_back(((mchar >> 7) & 1) % plaintextModules);
        vShorts.push_back(((mchar >> 6) & 1) % plaintextModules);
        vShorts.push_back(((mchar >> 5) & 1) % plaintextModules);
        vShorts.push_back(((mchar >> 4) & 1) % plaintextModules);
        vShorts.push_back(((mchar >> 3) & 1) % plaintextModules);
        vShorts.push_back(((mchar >> 2) & 1) % plaintextModules);
        vShorts.push_back(((mchar >> 1) & 1) % plaintextModules);
        vShorts.push_back(((mchar >> 0) & 1) % plaintextModules);
    }
    return cc->MakeCoefPackedPlaintext(vShorts);
}

Ciphertext<DCRTPoly> encrypt(CryptoContext<DCRTPoly> cc, PublicKey<DCRTPoly> pubKey, Plaintext pt) {
    return cc->Encrypt(pubKey, pt);
}

Plaintext decrypt(CryptoContext<DCRTPoly> cc,
        PrivateKey<DCRTPoly> secKey,
        Ciphertext<DCRTPoly> ct,
        size_t ptSize) {
    Plaintext pt;
    cc->Decrypt(secKey, ct, &pt);
    pt->SetLength(ptSize);
    return pt;
}

EvalKey<DCRTPoly> genReKey(CryptoContext<DCRTPoly> cc, PrivateKey<DCRTPoly> oldSecKey, PublicKey<DCRTPoly> newPubKey) {
    return cc->ReKeyGen(oldSecKey, newPubKey);
}

std::vector<int64_t> decodePlaintext(Plaintext pt, size_t ptSize) {
    std::vector<int64_t> unpacked = pt->GetCoefPackedValue();
    for(unsigned int j=0; j< ptSize; j++) {
        if (unpacked[j] < 0)
            unpacked[j] += plaintextModules;
    }
    return unpacked;
}

int main() {

    auto cc = init();
    // PRINT PARAMS
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

    // Perform Key Generation Operation
    KeyPair<DCRTPoly> keyPair1 = genKeyPair(cc);

    // Plaintext encoding
    std::string message = "Secret Hello World\n";
    std::vector<uint8_t> vec(message.begin(), message.end());
    Plaintext pt = encodePlainText(cc, vec);
    auto ptSize = pt->GetLength();
    
    // Encryption
    auto ct1 = encrypt(cc, keyPair1.publicKey, pt);
    
    // Decryption of ciphertext
    Plaintext ptDec1 = decrypt(cc, keyPair1.secretKey, ct1, ptSize);
    
    // Keygen Operation
    KeyPair<DCRTPoly> newKeyPair = genKeyPair(cc);
    EvalKey<DCRTPoly> reKey = genReKey(cc, keyPair1.secretKey, newKeyPair.publicKey);

    // Re-Encryption
    ct1 = cc->ReEncrypt(ct1, reKey);

    // Decryption of Re-Encryption
    Plaintext ptDec2 = decrypt(cc, newKeyPair.secretKey, ct1, ptSize);

    auto unpacked0 = pt->GetCoefPackedValue();
    auto unpacked1 = decodePlaintext(ptDec1, ptSize);
    auto unpacked2 = decodePlaintext(ptDec2, ptSize);

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
