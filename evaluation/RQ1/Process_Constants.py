import numpy as np
import pandas as pd
import pickle

def calculate_ratio(arr):
    return np.sum(arr) / len(arr)

columns_AES = [
    'RijnDael_AES_Base', 'RijnDael_AES_inv_LONG', 'RijnDael_AES_LONG',
    'RijnDael_AES_Sbox1', 'RijnDael_AES_Sbox10', 'RijnDael_AES_Sbox11',
    'RijnDael_AES_Sbox12', 'RijnDael_AES_Sbox13', 'RijnDael_AES_Sbox14',
    'RijnDael_AES_Sbox15', 'RijnDael_AES_Sbox2', 'RijnDael_AES_Sbox3',
    'RijnDael_AES_Sbox4', 'RijnDael_AES_Sbox5', 'RijnDael_AES_Sbox6',
    'RijnDael_AES_Sbox7', 'RijnDael_AES_Sbox8', 'RijnDael_AES_Sbox9'
]

columns_ChaCha_Salsa20 = [
    'Chacha_256_constant', 'salsa20'
]

columns_TEA = [
    'TEA_DELTA', 'TEAN'
]

columns_RSA_1 = [
    'Big_Numbers0','Big_Numbers1', 'Big_Numbers2', 'Big_Numbers3', 'Big_Numbers4', 'Big_Numbers5',
    'Prime_Constants_long', 'RIPEMD160_Constants'
]
columns_RSA_2 = [
    'SHA1_Constants', 'SHA256_Constants', 'SHA512_Constants'
]

columns_NIST = [
    'NIST_B_163', 'NIST_B_233', 'NIST_K_163', 'NIST_K_233', 'NIST_P_192', 'NIST_P_224', 'NIST_P_256', 'NIST_P_384', 'NIST_P_521'
]

columns_SECG = [
    "SECG_secp192r1", "SECG_secp224r1", "SECG_secp256r1", "SECG_secp384r1",
    "SECG_secp521r1", "SECG_sect163k1", "SECG_sect163r2", "SECG_sect233k1",
    "SECG_sect233r1", "SECG_sect283k1", "SECG_sect283r1", "SECG_sect409k1",
    "SECG_sect409r1", "SECG_sect571k1", "SECG_sect571r1"
]


file_path_R = 'Encryption_Algorithm_Constants_Ransomware.csv'
data_R = pd.read_csv(file_path_R)

AES_R = np.array((data_R[columns_AES].sum(axis=1)>0).astype(int))

DES_R = np.array(data_R["DES_sbox"]).astype(int)

SM4_R = np.array(data_R["SM4_sbox"]).astype(int)

ChaCha_Salsa20_R = np.array((data_R[columns_ChaCha_Salsa20].sum(axis=1)>0).astype(int))

Camellia_R = np.zeros(len(AES_R), dtype=int)

Blowfish_R = np.zeros(len(AES_R), dtype=int)

Twofish_R = np.zeros(len(AES_R), dtype=int)

TEA_R = np.array((data_R[columns_TEA].sum(axis=1)>0).astype(int))

Rabbit_R = np.zeros(len(AES_R), dtype=int)

RC4_IDEA_HC_256_R = np.zeros(len(AES_R), dtype=int)

RSA_PKCS1_R = np.bitwise_and(np.array((data_R[columns_RSA_1].sum(axis=1) > 0).astype(int)), np.array((data_R[columns_RSA_2].sum(axis=1) > 0).astype(int)))

ECC_NIST_R = np.array((data_R[columns_NIST].sum(axis=1)>0).astype(int))

ECC_SECG_R = np.array((data_R[columns_SECG].sum(axis=1)>0).astype(int))

ECC_Brainpool_R = np.array(data_R["brainpool_brainpoolP160r1"]).astype(int)

ECC_Curve25519_R = np.array(data_R["Curve25519"]).astype(int)

ECC_Curve448_R = np.zeros(len(AES_R), dtype=int)


ratios_R = {
    "File_R":data_R["File"],
    "AES_R": calculate_ratio(AES_R),
    "DES_R": calculate_ratio(DES_R),
    "SM4_R": calculate_ratio(SM4_R),
    "ChaCha_Salsa20_R": calculate_ratio(ChaCha_Salsa20_R),
    "Camellia_R": calculate_ratio(Camellia_R),
    "Blowfish_R": calculate_ratio(Blowfish_R),
    "Twofish_R": calculate_ratio(Twofish_R),
    "TEA_R": calculate_ratio(TEA_R),
    "Rabbit_R": calculate_ratio(Rabbit_R),
    "RC4_IDEA_HC_256_R": calculate_ratio(RC4_IDEA_HC_256_R),
    "RSA_PKCS1_R": calculate_ratio(RSA_PKCS1_R),
    "ECC_NIST_R": calculate_ratio(ECC_NIST_R),
    "ECC_SECG_R": calculate_ratio(ECC_SECG_R),
    "ECC_Brainpool_R": calculate_ratio(ECC_Brainpool_R),
    "ECC_Curve25519_R": calculate_ratio(ECC_Curve25519_R),
    "ECC_Curve448_R": calculate_ratio(ECC_Curve448_R)
}

arrays = [AES_R, DES_R, SM4_R, ChaCha_Salsa20_R, Camellia_R, Blowfish_R, Twofish_R, TEA_R, Rabbit_R, RC4_IDEA_HC_256_R, RSA_PKCS1_R, ECC_SECG_R, ECC_Brainpool_R, ECC_Curve25519_R, ECC_Curve448_R]

total_const_R = np.zeros_like(arrays[0], dtype=int)

for array in arrays:
    total_const_R = np.bitwise_or(total_const_R, array)

ratios_R['total_const_R'] = calculate_ratio(total_const_R)
ratios_R['have_constant_R'] = total_const_R


print(ratios_R)

output_file = 'ratios_constants_ransomware.pkl'

with open(output_file, 'wb') as file:
    pickle.dump(ratios_R, file)


file_path_B = 'Encryption_Algorithm_Constants_Benign.csv'
data_B = pd.read_csv(file_path_B)

AES_B = np.array((data_B[columns_AES].sum(axis=1)>0).astype(int))

DES_B = np.array(data_B["DES_sbox"]).astype(int)

SM4_B = np.zeros(len(AES_B), dtype=int)

ChaCha_Salsa20_B = np.zeros(len(AES_B), dtype=int)

Camellia_B = np.zeros(len(AES_B), dtype=int)

Blowfish_B = np.zeros(len(AES_B), dtype=int)

Twofish_B = np.zeros(len(AES_B), dtype=int)

TEA_B = np.array(data_B['TEA_DELTA']).astype(int)

Rabbit_B = np.zeros(len(AES_B), dtype=int)

RC4_IDEA_HC_256_B = np.zeros(len(AES_B), dtype=int)

RSA_PKCS1_B = np.bitwise_and(np.array((data_B[columns_RSA_1].sum(axis=1) > 0).astype(int)), np.array((data_B[columns_RSA_2].sum(axis=1) > 0).astype(int)))

ECC_NIST_B = np.array((data_B[columns_NIST].sum(axis=1)>0).astype(int))

ECC_SECG_B = np.array((data_B[columns_SECG].sum(axis=1)>0).astype(int))

ECC_Brainpool_B = np.zeros(len(AES_B), dtype=int)

ECC_Curve25519_B = np.zeros(len(AES_B), dtype=int)

ECC_Curve448_B = np.zeros(len(AES_B), dtype=int)


ratios_B = {
    "File_B": data_B["File"],
    "AES_B": calculate_ratio(AES_B),
    "DES_B": calculate_ratio(DES_B),
    "SM4_B": calculate_ratio(SM4_B),
    "ChaCha_Salsa20_B": calculate_ratio(ChaCha_Salsa20_B),
    "Camellia_B": calculate_ratio(Camellia_B),
    "Blowfish_B": calculate_ratio(Blowfish_B),
    "Twofish_B": calculate_ratio(Twofish_B),
    "TEA_B": calculate_ratio(TEA_B),
    "Rabbit_B": calculate_ratio(Rabbit_B),
    "RC4_IDEA_HC_256_B": calculate_ratio(RC4_IDEA_HC_256_B),
    "RSA_PKCS1_B": calculate_ratio(RSA_PKCS1_B),
    "ECC_NIST_B": calculate_ratio(ECC_NIST_B),
    "ECC_SECG_B": calculate_ratio(ECC_SECG_B),
    "ECC_Brainpool_B": calculate_ratio(ECC_Brainpool_B),
    "ECC_Curve25519_B": calculate_ratio(ECC_Curve25519_B),
    "ECC_Curve448_B": calculate_ratio(ECC_Curve448_B)
}

arrays = [AES_B, DES_B, SM4_B, ChaCha_Salsa20_B, Camellia_B, Blowfish_B, Twofish_B, TEA_B, Rabbit_B, RC4_IDEA_HC_256_B, RSA_PKCS1_B, ECC_SECG_B, ECC_Brainpool_B, ECC_Curve25519_B, ECC_Curve448_B]

total_const_B = np.zeros_like(arrays[0], dtype=int)

for array in arrays:
    total_const_B = np.bitwise_or(total_const_B, array)

ratios_B['total_const_B'] = calculate_ratio(total_const_B)
ratios_B['have_constant_B'] = total_const_B

print(ratios_B)

output_file = 'ratios_constants_benign.pkl'

with open(output_file, 'wb') as file:
    pickle.dump(ratios_B, file)

