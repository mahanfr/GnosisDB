/*
* fn gen_key() -> (sk, pk)
* fn regen_key(sk, pk, N, t) -> [kFrag; N]
* fn encrypt(pk) -> (K , capsule)
* fn decrypt(sk, capsule) -> K | None
* fn re_encrypt(kfrag, capsule) -> Cfrag | None
* fn de_encrypt_frags(sk, [Cfrag| t], capsule) -> K | None 
*/
use umbral_pre::*;

pub fn generate_keys() -> (SecretKey, PublicKey) {
    let sk = SecretKey::random();
    let pk = sk.public_key();
    (sk, pk)
}

pub fn generate_signer() -> (Signer, PublicKey) {
    let signer = Signer::new(SecretKey::random());
    let verifying_pk = signer.verifying_key();
    (signer, verifying_pk)
}

pub fn unverify_kfrags(vkfrags : Box<[VerifiedKeyFrag]>) -> Vec<KeyFrag> {
    let mut kfrags = Vec::new();
    for frag in vkfrags.iter() {
        kfrags.push(frag.clone().unverify());
    }
    kfrags
}

fn main() {
    let (old_sk, old_pk) = generate_keys();
    let (signer, signer_pk) = generate_signer();

    let (new_sk, new_pk) = generate_keys();

    let plaintext = b"Hello cummy man";
    let (capsule, ciphertext) = encrypt(&old_pk, plaintext).unwrap();
    
    // let plaintext = decrypt_original(&old_sk, &capsule, &ciphertext).unwrap();
    // assert_eq!(&plaintext as &[u8], plaintext);

    let verified_kfrags = generate_kfrags(&old_sk, &new_pk, &signer, 2, 3, true, true);
    
    // *** over network ***
    let kfrags = unverify_kfrags(verified_kfrags);
    // *** over network ***
    
    let vkfrag0 = kfrags[0].clone().verify(&signer_pk, Some(&old_pk), Some(&new_pk)).unwrap();
    let vcfrag0 = reencrypt(&capsule, vkfrag0);

    let vkfrag1 = kfrags[1].clone().verify(&signer_pk, Some(&old_pk), Some(&new_pk)).unwrap();
    let vcfrag1 = reencrypt(&capsule, vkfrag1);

    // *** over network ***
    let cfrag0 = vcfrag0.clone().unverify();
    let cfrag1 = vcfrag1.clone().unverify();
    // *** over network ***

    let verified_cfrag0 = cfrag0
        .verify(&capsule, &signer_pk, &old_pk, &new_pk)
        .unwrap();
    let verified_cfrag1 = cfrag1
        .verify(&capsule, &signer_pk, &old_pk, &new_pk)
        .unwrap();
    //
    //  &new_sk
    //  &old_pk
    //  &capsule
    //  [verified_cfrag0, verified_cfrag1]
    //  &ciphertext
    //
    // let plaintext_bob = decrypt_reencrypted(&new_sk, &old_pk, &capsule, [verified_cfrag0, verified_cfrag1], &ciphertext).unwrap();
    // println!("{}", String::from_utf8_lossy(&plaintext_bob));

}
