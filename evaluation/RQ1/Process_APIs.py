import numpy as np
import pandas as pd
import pickle

def calculate_ratio(arr):
    return np.sum(arr) / len(arr)



file_path_R = 'OS_API_Ransomware.csv'
data_R = pd.read_csv(file_path_R)

encryption_evidence = [
    'BCryptEnumContextFunctionProvider', 'BCryptEnumProviders', 'CryptAcquireContext', 'CryptEnumProviders',
    'CryptGetDefaultProvider', 'CryptReleaseContext', 'CryptSetProvParam', 'FreeCryptProvFromCert',
    'BCryptDeriveKey', 'BCryptDestroyKey', 'BCryptDuplicateKey', 'BCryptExportKey',
    'BCryptGenerateKeyPair', 'BCryptGenerateSymmetricKey', 'BCryptImportKey', 'BCryptImportKeyPair',
    'BCryptKeyDerivation', 'CryptDeriveKey', 'CryptDestroyKey', 'CryptDuplicateKey', 'CryptExportKey',
    'CryptGenKey', 'CryptGetUserKey', 'CryptImportKey', 'CryptImportPublicKeyInfo', 'CryptSetKeyParam',
    'BCryptEncrypt', 'CryptEncrypt', 'CryptProtectData', 'CryptProtectMemory', 'EncryptFile',
    'LZRead', 'ReadFile', 'LZOpenFile', 'OpenFile', 'OpenFileByld', 'CreateFile',
    'DeleteFile', 'MoveFile', 'WriteFile',
    'FindFirstFile', 'SearchPath', 'FindNextFile',
]


crypto_APIs = ["CryptAcquireContext","BCryptImportKey","BCryptImportKeyPair","CryptDeriveKey","CryptDestroyKey","CryptExportKey","CryptImportKey","CryptImportPublicKeyInfo","BCryptEncrypt","CryptEncrypt"]

filesystem_APIs = ["ReadFile","OpenFile","CreateFile","DeleteFile","MoveFile","WriteFile","FindFirstFile","FindNextFile"]



ratios_API_R = {
    "File_R":data_R["File"],
}
for api in encryption_evidence:
    try:
        ratios_API_R[api + "_R"] = calculate_ratio(np.array(data_R[api]).astype(int))
    except:
        ratios_API_R[api + "_R"] = 0

total_cry_R = np.zeros(len(data_R["File"]), dtype=int)
for cry_API in crypto_APIs:
    total_cry_R = np.bitwise_or(total_cry_R, np.array(data_R[cry_API]).astype(int))

total_file_R = np.zeros(len(data_R["File"]), dtype=int)
for file_API in filesystem_APIs:
    total_file_R = np.bitwise_or(total_file_R, np.array(data_R[file_API]).astype(int))

total_R = np.bitwise_or(total_cry_R, total_file_R)

ratios_API_R['total_cry_API_R'] = calculate_ratio(total_cry_R)
ratios_API_R['have_cry_API_R'] = total_cry_R

ratios_API_R['total_file_API_R'] = calculate_ratio(total_file_R)
ratios_API_R['have_file_API_R'] = total_file_R

ratios_API_R['total_API_R'] = calculate_ratio(total_R)
ratios_API_R['have_API_R'] = total_R

print(ratios_API_R)

output_file = 'ratios_API_ransomware.pkl'

with open(output_file, 'wb') as file:
    pickle.dump(ratios_API_R, file)



file_path_B = 'OS_API_Benign.csv'
data_B = pd.read_csv(file_path_B)


ratios_API_B = {
    "File_B":data_B["File"],
}

for api in encryption_evidence:
    try:
        ratios_API_B[api + "_B"] = calculate_ratio(np.array(data_B[api]).astype(int))
    except:
        ratios_API_B[api + "_B"] = 0

total_cry_B = np.zeros(len(data_B["File"]), dtype=int)
for cry_API in crypto_APIs:
    total_cry_B = np.bitwise_or(total_cry_B, np.array(data_B[cry_API]).astype(int))

total_file_B = np.zeros(len(data_B["File"]), dtype=int)
for file_API in filesystem_APIs:
    total_file_B = np.bitwise_or(total_file_B, np.array(data_B[file_API]).astype(int))

total_B = np.bitwise_or(total_cry_B, total_file_B)

ratios_API_B['total_cry_API_B'] = calculate_ratio(total_cry_B)
ratios_API_B['have_cry_API_B'] = total_cry_B

ratios_API_B['total_file_API_B'] = calculate_ratio(total_file_B)
ratios_API_B['have_file_API_B'] = total_file_B

ratios_API_B['total_API_B'] = calculate_ratio(total_B)
ratios_API_B['have_API_B'] = total_B


print(ratios_API_B)

output_file = 'ratios_API_benign.pkl'

with open(output_file, 'wb') as file:
    pickle.dump(ratios_API_B, file)


