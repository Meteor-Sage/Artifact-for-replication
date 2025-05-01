import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch
import matplotlib as mpl
import pickle

def calculate_ratio(arr):
    return np.sum(arr) / len(arr)

with open('ratios_constants_ransomware.pkl', 'rb') as file:
    ratios_R = pickle.load(file)

with open('ratios_constants_benign.pkl', 'rb') as file:
    ratios_B = pickle.load(file)

with open('ratios_API_ransomware.pkl', 'rb') as file:
    ratios_API_R = pickle.load(file)

with open('ratios_API_benign.pkl', 'rb') as file:
    ratios_API_B = pickle.load(file)

mpl.rcParams['font.family'] = 'Times New Roman'
mpl.rcParams['font.weight'] = 'normal'
mpl.rcParams['mathtext.default'] = 'regular'


encryption_evidence = [
    'BCryptEnumContext\nFunctionProvider', 'BCryptEnumProviders', 'CryptAcquireContext', 'CryptEnumProviders',
    'CryptGetDefaultProvider', 'CryptReleaseContext', 'CryptSetProvParam', 'FreeCryptProvFromCert',
    'BCryptDeriveKey', 'BCryptDestroyKey', 'BCryptDuplicateKey', 'BCryptExportKey',
    'BCryptGenerateKeyPair', 'BCryptGenerateSymmetricKey', 'BCryptImportKey', 'BCryptImportKeyPair',
    'BCryptKeyDerivation', 'CryptDeriveKey', 'CryptDestroyKey', 'CryptDuplicateKey', 'CryptExportKey',
    'CryptGenKey', 'CryptGetUserKey', 'CryptImportKey', 'CryptImportPublicKeyInfo', 'CryptSetKeyParam',
    'BCryptEncrypt', 'CryptEncrypt', 'CryptProtectData', 'CryptProtectMemory', 'EncryptFile',

    'LZRead','ReadFile','LZOpenFile','OpenFile','OpenFileByld','CreateFile',
    'DeleteFile','MoveFile','WriteFile',
    'FindFirstFile','SearchPath','FindNextFile',

    'Total of OS API',


    'AES', 'DES', 'SM4', 'ChaCha/Salsa20', 'Camellia', 'Blowfish', 'Twofish', 'TEA',
    'Rabbit', 'RC4/IDEA/HC-256', 'RSA-PKCS1', 'ECC-NIST', 'ECC-SECG', 'ECC-Brainpool',
    'ECC-Curve25519', 'ECC-Curve448', 'Total of Encryption Constants', ''
]
malicious = [
    ratios_API_R['BCryptEnumContextFunctionProvider_R'], ratios_API_R['BCryptEnumProviders_R'], ratios_API_R['CryptAcquireContext_R'], ratios_API_R['CryptEnumProviders_R'], ratios_API_R['CryptGetDefaultProvider_R'], ratios_API_R['CryptReleaseContext_R'], ratios_API_R['CryptSetProvParam_R'], ratios_API_R['FreeCryptProvFromCert_R'],
    ratios_API_R['BCryptDeriveKey_R'], ratios_API_R['BCryptDestroyKey_R'], ratios_API_R['BCryptDuplicateKey_R'], ratios_API_R['BCryptExportKey_R'], ratios_API_R['BCryptGenerateKeyPair_R'], ratios_API_R['BCryptGenerateSymmetricKey_R'], ratios_API_R['BCryptImportKey_R'],
    ratios_API_R['BCryptImportKeyPair_R'], ratios_API_R['BCryptKeyDerivation_R'], ratios_API_R['CryptDeriveKey_R'], ratios_API_R['CryptDestroyKey_R'], ratios_API_R['CryptDuplicateKey_R'], ratios_API_R['CryptExportKey_R'],
    ratios_API_R['CryptGenKey_R'], ratios_API_R['CryptGetUserKey_R'], ratios_API_R['CryptImportKey_R'], ratios_API_R['CryptImportPublicKeyInfo_R'],
    ratios_API_R['CryptSetKeyParam_R'], ratios_API_R['BCryptEncrypt_R'], ratios_API_R['CryptEncrypt_R'], ratios_API_R['CryptProtectData_R'],
    ratios_API_R['CryptProtectMemory_R'],ratios_API_R['EncryptFile_R'],


    ratios_API_R['LZRead_R'],ratios_API_R['ReadFile_R'],ratios_API_R['LZOpenFile_R'],ratios_API_R['OpenFile_R'],ratios_API_R['OpenFileByld_R'],ratios_API_R['CreateFile_R'],
    ratios_API_R['DeleteFile_R'],ratios_API_R['MoveFile_R'],ratios_API_R['WriteFile_R'],
    ratios_API_R['FindFirstFile_R'],ratios_API_R['SearchPath_R'],ratios_API_R['FindNextFile_R'],

    ratios_API_R['total_API_R'],




    ratios_R["AES_R"], ratios_R["DES_R"], ratios_R["SM4_R"], ratios_R["ChaCha_Salsa20_R"], ratios_R["Camellia_R"], ratios_R["Blowfish_R"], ratios_R["Twofish_R"], ratios_R["TEA_R"], ratios_R["Rabbit_R"], ratios_R["RC4_IDEA_HC_256_R"],
    ratios_R["RSA_PKCS1_R"], ratios_R["ECC_NIST_R"], ratios_R["ECC_SECG_R"], ratios_R["ECC_Brainpool_R"], ratios_R["ECC_Curve25519_R"], ratios_R["ECC_Curve448_R"],

    ratios_R["total_const_R"], 0
]
benign = [
    ratios_API_B['BCryptEnumContextFunctionProvider_B'], ratios_API_B['BCryptEnumProviders_B'], ratios_API_B['CryptAcquireContext_B'], ratios_API_B['CryptEnumProviders_B'], ratios_API_B['CryptGetDefaultProvider_B'], ratios_API_B['CryptReleaseContext_B'], ratios_API_B['CryptSetProvParam_B'], ratios_API_B['FreeCryptProvFromCert_B'],
    ratios_API_B['BCryptDeriveKey_B'], ratios_API_B['BCryptDestroyKey_B'], ratios_API_B['BCryptDuplicateKey_B'], ratios_API_B['BCryptExportKey_B'], ratios_API_B['BCryptGenerateKeyPair_B'], ratios_API_B['BCryptGenerateSymmetricKey_B'], ratios_API_B['BCryptImportKey_B'],
    ratios_API_B['BCryptImportKeyPair_B'], ratios_API_B['BCryptKeyDerivation_B'], ratios_API_B['CryptDeriveKey_B'], ratios_API_B['CryptDestroyKey_B'], ratios_API_B['CryptDuplicateKey_B'], ratios_API_B['CryptExportKey_B'],
    ratios_API_B['CryptGenKey_B'], ratios_API_B['CryptGetUserKey_B'], ratios_API_B['CryptImportKey_B'], ratios_API_B['CryptImportPublicKeyInfo_B'],
    ratios_API_B['CryptSetKeyParam_B'], ratios_API_B['BCryptEncrypt_B'], ratios_API_B['CryptEncrypt_B'], ratios_API_B['CryptProtectData_B'],
    ratios_API_B['CryptProtectMemory_B'],ratios_API_B['EncryptFile_B'],


    ratios_API_B['LZRead_B'],ratios_API_B['ReadFile_B'],ratios_API_B['LZOpenFile_B'],ratios_API_B['OpenFile_B'],ratios_API_B['OpenFileByld_B'],ratios_API_B['CreateFile_B'],
    ratios_API_B['DeleteFile_B'],ratios_API_B['MoveFile_B'],ratios_API_B['WriteFile_B'],
    ratios_API_B['FindFirstFile_B'],ratios_API_B['SearchPath_B'],ratios_API_B['FindNextFile_B'],


    ratios_API_B['total_API_B'],

    ratios_B["AES_B"], ratios_B["DES_B"], ratios_B["SM4_B"], ratios_B["ChaCha_Salsa20_B"], ratios_B["Camellia_B"],
    ratios_B["Blowfish_B"], ratios_B["Twofish_B"], ratios_B["TEA_B"], ratios_B["Rabbit_B"], ratios_B["RC4_IDEA_HC_256_B"],
    ratios_B["RSA_PKCS1_B"], ratios_B["ECC_NIST_B"], ratios_B["ECC_SECG_B"], ratios_B["ECC_Brainpool_B"], ratios_B["ECC_Curve25519_B"], ratios_B["ECC_Curve448_B"],

    ratios_B["total_const_B"], 0
]



print(f"Overall, {ratios_API_R['total_API_R']:.2f} of ransomware samples exhibit notable OS API usage characteristics, and {ratios_API_R['total_cry_API_R']:.2f} of ransomware samples exhibit notable OS API usage characteristics exclusive of filesystem APIs, which is six times higher than the {ratios_API_B['total_cry_API_B']:.2f} proportion observed in benign samples.")

print(f"In total, {ratios_R['total_const_R']:.2f} of ransomware samples exhibit the usage of encryption algorithms, indicated by the presence of the encryption algorithm constants, which is more than thirteen times higher than the {ratios_B['total_const_B']:.2f} proportion observed in benign samples. In total, we observed {calculate_ratio(np.bitwise_or(ratios_API_R['have_API_R'],ratios_R['have_constant_R'])):.2f} ransomware samples exhibiting the use of either OS APIs or encryption algorithm constants, and {calculate_ratio(np.bitwise_or(ratios_API_R['have_cry_API_R'],ratios_R['have_constant_R'])):.2f} ransomware samples exhibiting the use of either OS APIs or encryption algorithm constants excluding filesystem APIs.")


function_index = encryption_evidence.index('Total of OS API') + 1


encryption_evidence_api = encryption_evidence[:function_index].copy()
encryption_evidence_api[-1] = ' '

malicious_api = malicious[:function_index]
benign_api = benign[:function_index]


encryption_evidence_alg = encryption_evidence[function_index:-1].copy()
encryption_evidence_alg[-1] = ' '

malicious_alg = malicious[function_index:-1]
benign_alg = benign[function_index:-1]


api_categories = {
    'Cryptographic service\nprovider (CSP) APIs': slice(0, 8),
    'Key-related\nAPIs': slice(8, 26),
    'Encryption\nAPIs': slice(26, 31),
    'Filesystem\nAPIs':slice(31,44)
}

algorithm_categories = {
    'Symmetric\nAlgorithms': slice(0, encryption_evidence_alg.index('RSA-PKCS1')),
    'Asymmetric\nAlgorithms': slice(encryption_evidence_alg.index('RSA-PKCS1'), -1)
}

def plot_with_right_labels_1(names, mal_data, ben_data, categories, colors, filename):
    filtered_indices = [i for i in range(len(names)) if not (mal_data[i] == 0.0 and ben_data[i] == 0.0)]
    filtered_names = [names[i] for i in filtered_indices]
    filtered_mal = [mal_data[i] for i in filtered_indices]
    filtered_ben = [ben_data[i] for i in filtered_indices]
    
    y = np.arange(len(filtered_names))
    height = 0.4

    fig, ax = plt.subplots(figsize=(14, len(filtered_names) * 0.4 + 2))

    ax.barh(y - height/2, filtered_mal, height=height, color=colors['mal'], label='Ransomware')
    ax.barh(y + height/2, filtered_ben, height=height, color=colors['ben'], hatch='//', label='Benign Sample',edgecolor="white")

    split_positions = []

    if 'TEA' in filtered_names and 'RSA-PKCS1' in filtered_names:
        tea_idx = filtered_names.index('TEA')
        rsa_idx = filtered_names.index('RSA-PKCS1')
        if tea_idx + 1 == rsa_idx:
            split_positions.append(y[rsa_idx] - 0.6)

    for cat_slice in categories.values():

        first_in_filtered = None
        for i, orig_idx in enumerate(filtered_indices):
            if orig_idx in range(cat_slice.start, cat_slice.stop):
                first_in_filtered = i
                break
        
        if first_in_filtered is not None and first_in_filtered > 0:
            split_positions.append(y[first_in_filtered] - 0.6)

    for pos in split_positions:
        ax.axhline(pos, color='gray', linestyle='--', alpha=0.7, xmax=0.98, zorder=0)

    for cat_name, cat_slice in categories.items():
        visible_indices = [i for i in range(cat_slice.start, cat_slice.stop) 
                         if i in filtered_indices]
        
        if visible_indices:
            first_idx = filtered_indices.index(visible_indices[0])
            last_idx = filtered_indices.index(visible_indices[-1])
            middle_y = (y[first_idx] + y[last_idx]) / 2-0.28
        else:
            if cat_name == 'Asymmetric\nAlgorithms':
                rsa_pos = names.index('RSA-PKCS1')
                if rsa_pos < len(filtered_indices):
                    middle_y = y[filtered_indices.index(rsa_pos)] + 0.5
                else:
                    middle_y = y[-1] + 0.45
            else:
                middle_y = y[len(y)//2]-1
        
        ax.text(1.1, middle_y, cat_name,
                ha='left', va='center', 
                fontsize=18, color='black', fontweight='bold', family='Times New Roman')

    ax.set_yticks(y)
    ax.set_yticklabels(filtered_names, fontsize=18, family='Times New Roman')
    ax.tick_params(axis='x', labelsize=20)
    ax.invert_yaxis()
    ax.set_xlabel('Percentage', fontsize=25, family='Times New Roman')

    ax.set_xlim(left=0, right=1.45)
    ax.set_xticks(np.arange(0, 1.05, 0.1))

    for spine in ax.spines.values():
        spine.set_visible(True)
        spine.set_color('black')
        spine.set_linewidth(1)


    for i, (mal_val, ben_val) in enumerate(zip(filtered_mal, filtered_ben)):
        if mal_val > 0.005:
            formatted_mal = f"{mal_val:.3f}".rstrip('0').rstrip('.') if round(mal_val, 2) == 0 else f"{mal_val:.2f}".rstrip('0').rstrip('.')
            ax.text(mal_val + 0.004, i - height/2, formatted_mal,
                    va='center', fontsize=18, family='Times New Roman')
        if ben_val > 0.005:
            formatted_ben = f"{ben_val:.3f}".rstrip('0').rstrip('.') if round(ben_val, 2) == 0 else f"{ben_val:.2f}".rstrip('0').rstrip('.')
            ax.text(ben_val + 0.004, i + height/2 + 0.08, formatted_ben,
                    va='center', fontsize=18, family='Times New Roman')


    ax.legend(
        handles=[
            Patch(color=colors['mal'],label='Ransomware'),
            Patch(facecolor=colors['ben'], hatch='//', edgecolor='white', label='Benign Sample')
        ],
        loc='upper right',
        bbox_to_anchor=(1.01, 0.13),
        frameon=False,
        prop={'family': 'Times New Roman', 'size': 18}
    )


    if ' ' in filtered_names:
        total_idx = list(filtered_names).index(' ')

        ax.text(-0.089, total_idx, 'Total ',
                va='center', ha='left',
                fontsize=18, weight='bold', family='Times New Roman', color='black')


    plt.subplots_adjust(left=0.28, right=0.75)
    
    plt.tight_layout()
    plt.savefig(filename, format='pdf', bbox_inches='tight', dpi=300)
    plt.close()



plot_with_right_labels_1(
    names=encryption_evidence_api,
    mal_data=malicious_api,
    ben_data=benign_api,
    categories=api_categories,
    colors={'mal': '#D62728', 'ben': '#1F77B4'},
    filename='Fig7.pdf'
)

def plot_with_right_labels_2(names, mal_data, ben_data, categories, colors, filename):
    filtered_indices = [i for i in range(len(names)) if not (mal_data[i] == 0.0 and ben_data[i] == 0.0)]
    filtered_names = [names[i] for i in filtered_indices]
    filtered_mal = [mal_data[i] for i in filtered_indices]
    filtered_ben = [ben_data[i] for i in filtered_indices]
    
    y = np.arange(len(filtered_names))
    height = 0.4

    fig, ax = plt.subplots(figsize=(14, len(filtered_names) * 0.4 + 2))

    ax.barh(y - height/2, filtered_mal, height=height, color=colors['mal'],label='Ransomware')
    ax.barh(y + height/2, filtered_ben, height=height, color=colors['ben'], hatch='//',label='Benign Sample',edgecolor="white")


    split_positions = []

    if 'TEA' in filtered_names and 'RSA-PKCS1' in filtered_names:
        tea_idx = filtered_names.index('TEA')
        rsa_idx = filtered_names.index('RSA-PKCS1')
        if tea_idx + 1 == rsa_idx:
            split_positions.append(y[rsa_idx] - 0.6)

    for cat_slice in categories.values():
        first_in_filtered = None
        for i, orig_idx in enumerate(filtered_indices):
            if orig_idx in range(cat_slice.start, cat_slice.stop):
                first_in_filtered = i
                break
        
        if first_in_filtered is not None and first_in_filtered > 0:
            split_positions.append(y[first_in_filtered] - 0.6)

    for pos in split_positions:
        ax.axhline(pos, color='gray', linestyle='--', alpha=0.7, xmax=0.98, zorder=0)

    for cat_name, cat_slice in categories.items():
        visible_indices = [i for i in range(cat_slice.start, cat_slice.stop) 
                         if i in filtered_indices]
        
        if visible_indices:
            first_idx = filtered_indices.index(visible_indices[0])
            last_idx = filtered_indices.index(visible_indices[-1])
            middle_y = (y[first_idx] + y[last_idx]) / 2
        else:
            if cat_name == 'Asymmetric\nAlgorithms':
                rsa_pos = names.index('RSA-PKCS1')
                if rsa_pos < len(filtered_indices):
                    middle_y = y[filtered_indices.index(rsa_pos)] + 0.5
                else:
                    middle_y = y[-1] + 0.5
            else:
                middle_y = y[len(y)//2]
        
        ax.text(1.1, middle_y, cat_name,
                ha='left', va='center', 
                fontsize=18, color='black', fontweight='bold', family='Times New Roman')

    ax.set_yticks(y)
    ax.set_yticklabels(filtered_names, fontsize=18, family='Times New Roman')
    ax.tick_params(axis='x', labelsize=20)
    ax.invert_yaxis()
    ax.set_xlabel('Percentage', fontsize=25, family='Times New Roman')

    ax.set_xlim(left=0, right=1.3)
    ax.set_xticks(np.arange(0, 1.05, 0.1))

    for spine in ax.spines.values():
        spine.set_visible(True)
        spine.set_color('black')
        spine.set_linewidth(1)


    for i, (mal_val, ben_val) in enumerate(zip(filtered_mal, filtered_ben)):
        if mal_val > 0:
            if mal_val <=0.005:
                formatted_mal = f"{mal_val:.3f}".rstrip('0').rstrip('.') 
                ax.text(mal_val + 0.004, i - height/2, formatted_mal,
                        va='center', fontsize=18, family='Times New Roman')
            else:
                formatted_mal = f"{mal_val:.2f}".rstrip('0').rstrip('.') 
                ax.text(mal_val + 0.004, i - height/2, formatted_mal,
                        va='center', fontsize=18, family='Times New Roman')
        if ben_val > 0:
            if ben_val <= 0.005:
                formatted_ben = f"{ben_val:.3f}".rstrip('0').rstrip('.') 
                ax.text(ben_val + 0.004, i + height/2 + 0.08, formatted_ben,
                        va='center', fontsize=18, family='Times New Roman')
            else:
                formatted_ben = f"{ben_val:.2f}".rstrip('0').rstrip('.') if round(ben_val, 2) == 0 else f"{ben_val:.2f}".rstrip('0').rstrip('.')
                ax.text(ben_val + 0.004, i + height/2 + 0.08, formatted_ben,
                        va='center', fontsize=18, family='Times New Roman')

    ax.legend(
        handles=[
            Patch(color=colors['mal'], label='Ransomware'),
            Patch(facecolor=colors['ben'], hatch='//', edgecolor='white', label='Benign Sample')
        ],
        loc='upper right',
        bbox_to_anchor=(1, 0.2),
        frameon=False,
        prop={'family': 'Times New Roman', 'size': 18}
    )

    if ' ' in filtered_names:
        total_idx = list(filtered_names).index(' ')
        ax.text(-0.07, total_idx, 'Total ',
                va='center', ha='left',
                fontsize=18, weight='bold', family='Times New Roman', color='black')

    plt.subplots_adjust(left=0.28, right=0.75)
    plt.tight_layout()
    plt.savefig(filename, format='pdf', bbox_inches='tight', dpi=300)
    plt.close()



plot_with_right_labels_2(
    names=encryption_evidence_alg, 
    mal_data=malicious_alg,
    ben_data=benign_alg,
    categories=algorithm_categories,
    colors={'mal': '#D62728', 'ben': '#1F77B4'},
    filename='Fig8.pdf'
)

print('Fig7, Fig8 generated')