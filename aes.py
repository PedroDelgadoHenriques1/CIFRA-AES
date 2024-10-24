import numpy as np

# Chave e mensagem em hexadecimal
chave = "0F1571C947D9E8590CB7ADD6AF7F6798"
mensagem = "0123456789ABCDEFFEDCBA9876543210"

"""
    A função reshape do NumPy altera a forma de um array sem mudar seus dados.
    - O número total de elementos deve permanecer o mesmo.
    - Sintaxe: novo_array = original_array.reshape(nova_forma).
    - Retorna uma nova visão do array original, podendo refletir alterações.
    """

# Função para converter hex string para matriz 4x4 e transpor linhas e colunas
def hex_para_matriz_transposta(hex_str):
    # Convertendo para inteiro
    bytes_array = [int(hex_str[i:i + 2], 16) for i in range(0, len(hex_str), 2)]
    matrix = np.array(bytes_array).reshape(4, 4)
    
    # Transpondo a matriz
    transposed_matrix = matrix.T
    
    # Convertendo a matriz transposta para hexadecimal
    hex_matrix = [[f"{byte:02X}" for byte in row] for row in transposed_matrix]
    
    return hex_matrix  # Retorna matriz em formato hexadecimal

# Convertendo chave e mensagem para matrizes transpostas
mensagem_transposta = hex_para_matriz_transposta(mensagem)
chave_transposta = hex_para_matriz_transposta(chave)

# Fazendo a impressão de matrizes transpostas da mensagem obtidas na tela
print("Matriz transposta da mensagem:")
for row in mensagem_transposta:
    print(row)

# Fazendo a impressão de matrizes transpostas da chave obtidas na tela
print("\nMatriz transposta da chave:")
for row in chave_transposta:
    print(row)

# Definindo constantes
Nb = 4  
Nk = 4  
Nr = 10 

#Tabela S-Box
S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    ]

#Tabela Rcon
RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 
    0x20, 0x40, 0x80, 0x1B, 0x36
]

# funcoes gerais
def rotacionar_palavra(word):
    return word[1:] + word[:1]   #tira do primeiro e coloca no ultimo byte


def sub_bytes(word):
    return [hex(S_BOX[int(byte, 16)])[2:].upper().zfill(2) for byte in word]

def sub_bytes(word):
    return [hex(S_BOX[int(byte, 16)]).upper()[2:].zfill(2) for byte in word] # substitui cada byte de acordo com a s-box


def xor_words(word1, word2):
    return [hex(int(word1[i], 16) ^ int(word2[i], 16))[2:].upper().zfill(2) for i in range(4)]

def expand_key(key_matrix):
    # Inicializa a lista de palavras a partir da chave
    w = []
    for i in range(4):
        w.append(key_matrix[:, i].tolist())

    expanded_key = []
    expanded_key.extend(w)

    for i in range(Nk, 4 * (Nr + 1)):
        temp = expanded_key[i - 1]

        if i % Nk == 0:
            temp = sub_bytes(rotacionar_palavra(temp))
            # Adiciona Rcon
            temp[0] = hex(int(temp[0], 16) ^ RCON[i // Nk - 1])[2:].upper().zfill(2)

        # Gera a nova palavra
        new_word = xor_words(expanded_key[i - Nk], temp)
        expanded_key.append(new_word)

    return expanded_key

# Expandindo a chave
chave_expandida = expand_key(np.array(chave_transposta))

# Imprimindo as palavras da chave expandida
print("\nChave expandida:")
for i, word in enumerate(chave_expandida):
    print(f'w{i}: {" ".join(word)}')


state = mensagem_transposta

def add_round_key(state, round_key):
    # Converte state e round_key para arrays NumPy, se ainda não forem
    state = np.array(state)
    round_key = np.array(round_key)

    # Converte o estado e a chave para inteiros
    state_int = np.array([[int(state[r][c], 16) for c in range(4)] for r in range(4)])
    round_key_int = np.array([[int(round_key[r][c], 16) for c in range(4)] for r in range(4)])

    # Realiza XOR entre o estado e a chave (inteiros)
    result = state_int ^ round_key_int

    # Converte de volta para hexadecimal
    result_hex = np.array([[f'{result[r][c]:02X}' for c in range(4)] for r in range(4)])
    
    return result_hex.T


def add_round_key_final(state, round_key):
    state = state.T

    state_int = np.array([[int(state[r, c], 16) for c in range(4)] for r in range(4)])
    round_key_int = np.array([[int(round_key[r, c], 16) for c in range(4)] for r in range(4)])

    result = state_int ^ round_key_int

    result_hex = np.array([[f'{result[r, c]:02X}' for c in range(4)] for r in range(4)])
    
    # print("Resultado do XOR:", result_hex.flatten())
    return result_hex


# print round 0
state = add_round_key(state, chave_transposta)
print("Rodada 0:", state)

# galouis_multiplicacao
def galouis_multiplicacao(a, b):
    p = 0  # Resultado
    for _ in range(8):
        if b & 1:  # se b é ímpar
            p ^= a  # soma em GF(2^8)
        high_bit = a & 0x80  # verifica se o bit mais significativo é 1
        a <<= 1  # multiplica a por 2
        if high_bit:  # se o bit mais significativo era 1
            a ^= 0x1b  # reduz pelo polinômio irreducível
        b >>= 1  # divide b por 2
    return p

# mix columns
def mix_columns(state):
    mix_columns_matrix = np.array([
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]
    ])

    new_state = np.zeros((4, 4), dtype=int)
    for c in range(4):
        for r in range(4):
            new_state[r, c] = (
                galouis_multiplicacao(mix_columns_matrix[r, 0], int(state[0, c], 16)) ^
                galouis_multiplicacao(mix_columns_matrix[r, 1], int(state[1, c], 16)) ^
                galouis_multiplicacao(mix_columns_matrix[r, 2], int(state[2, c], 16)) ^
                galouis_multiplicacao(mix_columns_matrix[r, 3], int(state[3, c], 16))
            ) % 0x100 

    new_state_hex = np.array([[f'{new_state[r, c]:02X}' for c in range(4)] for r in range(4)])
    
    return new_state_hex.T

# steps passando de 1 até 10


for round_number in range(1, 11):
    state = np.array(sub_bytes(state.flatten().tolist())).reshape(4, 4).T
    print(f"Rodada {round_number}, Apos Substitute Bytes: \n", state)
    print("================================================================================")

    state[1] = np.roll(state[1], -1)
    state[2] = np.roll(state[2], -2)
    state[3] = np.roll(state[3], -3)
    
    print(f"Rodada {round_number}, Apos Shift Rows:\n", state)

    if round_number < 10:
        state = mix_columns(state)
        print(f"Rodada {round_number}, Apos Mix Columns:\n", state)

    if round_number < 10:
        round_key = chave_expandida[round_number * 4:(round_number + 1) * 4]
        state = add_round_key(state, np.array(round_key)).T
        print(f"Rodada {round_number}, Apos Add Rodada chave:\n", state)
        
    else:
        round_key = chave_expandida[round_number * 4:(round_number + 1) * 4]
        state = add_round_key_final(state, np.array(round_key))
        print(f"Rodada {round_number}, Apos Add Rodada chave:\n", state)

# Texto cifrado obtido após o último round
print("Texto cifrado :\n", state)