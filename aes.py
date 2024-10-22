import numpy as np

import numpy as np

# Chave e mensagem em hexadecimal
chave = "0F1571C947D9E8590CB7ADD6AF7F6798"
mensagem = "0123456789ABCDEFFEDCBA9876543210"

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

# Imprimindo as matrizes transpostas
print("Matriz transposta da mensagem:")
for row in mensagem_transposta:
    print(row)

print("\nMatriz transposta da chave:")
for row in chave_transposta:
    print(row)

# Constante de RotWord para cada rodada (Rcon) do AES
Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

# S-box completa do AES (256 valores)
Sbox = [
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

# Função SubWord (substitui bytes usando a S-box do AES)
def sub_word(word):
    return [Sbox[b] for b in word]

# Função RotWord (roda 4 bytes para a esquerda)
def rot_word(word):
    return word[1:] + word[:1]

# Função que converte uma string hex para uma lista de inteiros
def hex_to_bytes(hex_str):
    return [int(hex_str[i:i + 2], 16) for i in range(0, len(hex_str), 2)]

# Função que converte uma lista de bytes para uma string hexadecimal
def bytes_to_hex(byte_list):
    return ' '.join(f'{b:02X}' for b in byte_list)

# Função para adicionar a chave da rodada (XOR com a chave da rodada)
def add_round_key(state, round_key):
    return [[state[i][j] ^ round_key[j] for j in range(4)] for i in range(4)]

# Função para expandir a chave AES (Key Expansion)
def expand_key(key_hex):
    key = hex_to_bytes(key_hex)
    expanded_key = []

    # Primeiras palavras da chave são a própria chave
    for i in range(4):
        expanded_key.append(key[4 * i: 4 * (i + 1)])

    # Expansão da chave para 44 palavras
    for i in range(4, 44):
        temp = expanded_key[i - 1][:]  # Copia a última palavra
        if i % 4 == 0:
            temp = sub_word(rot_word(temp))  # Aplica RotWord e SubWord
            temp[0] ^= Rcon[(i // 4) - 1]  # XOR com a constante Rcon

        # XOR com a palavra anterior
        word = [a ^ b for a, b in zip(expanded_key[i - 4], temp)]
        expanded_key.append(word)

    return expanded_key

# Função para imprimir a chave expandida
def print_expanded_key(expanded_key):
    for i, word in enumerate(expanded_key):
        print(f'w{i}:', bytes_to_hex(word))

# Expansão da chave
expanded_key = expand_key(chave)

print("\nChave expandida:")
print_expanded_key(expanded_key)

# Etapa 2, Rodada 0: Adicionar chave de rodada
def xor_arrays(block, round_key):
    # Verificar se o tamanho dos arrays é o mesmo
    if len(block) != len(round_key):
        raise ValueError("Os arrays devem ter o mesmo tamanho.")
    
    # Fazer a operação XOR para cada byte
    return [b ^ rk for b, rk in zip(block, round_key)]

def format_as_matrix_corrected(block):
    # Verificar se o bloco tem 16 bytes
    if len(block) != 16:
        raise ValueError("O bloco deve ter 16 bytes.")
    
    # Formatar como uma matriz 4x4 (AES usa matriz de colunas)
    matrix = [block[i::4] for i in range(4)]
    
    # Imprimir a matriz formatada
    print("Estado do bloco:")
    for row in matrix:
        print("\t".join([f"{hex(byte)[2:].upper().zfill(2)}" for byte in row]))

# Exemplo de uso
# Bloco de entrada em bytes
block = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xEF, 0xCC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]

# Chave expandida (w0, w1, w2, w3) concatenada
round_key = [0x0F, 0x15, 0x71, 0xC9, 0x47, 0xD9, 0xE8, 0x59, 0x1C, 0xB7, 0xAD, 0xD6, 0xAF, 0x7F, 0x67, 0x98]

# Aplicar a função XOR
updated_block = xor_arrays(block, round_key)

# Mostrar o resultado como matriz corrigida
format_as_matrix_corrected(updated_block)

#Step 3, Round 1: Substitute bytes 
# S-box fornecida
s_box = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16],
]

# Estado atual da matriz
state = [
    [0xAB, 0x8B, 0x89, 0x35],
    [0x05, 0x40, 0x7F, 0xF1],
    [0x18, 0x3F, 0xF0, 0xFC],
    [0xE4, 0x4E, 0x2F, 0xC4]
]




# Função para aplicar SubBytes usando a S-box
def sub_bytes(state):
    """Substitui os bytes do estado usando a tabela S-Box."""
    new_state = []  # Inicializa a nova matriz de estado

    for row in state:  # Percorre cada linha do estado
        new_row = []  # Inicializa a nova linha para armazenar os bytes substituídos

        for cell in row:  # Percorre cada byte na linha atual
            # Calcula os índices da S-Box
            row_idx = (cell >> 4) & 0x0F  # Obtém o índice da linha (quatro bits superiores)
            col_idx = cell & 0x0F         # Obtém o índice da coluna (quatro bits inferiores)

            # Substitui o byte usando a S-Box
            substituted_byte = s_box[row_idx][col_idx]  # Aplica a substituição
            new_row.append(substituted_byte)  # Adiciona o byte substituído à nova linha

        new_state.append(new_row)  # Adiciona a nova linha à nova matriz de estado

    return new_state  # Retorna a nova matriz de estado com os bytes substituídos


# Aplicando SubBytes
new_state = sub_bytes(state)

# Exibindo o estado resultante
# for row in new_state:
#     print([hex(cell) for cell in row])


#Step 4, Round 1: Shift rows
def shift_rows(state):
    # Primeira linha (não muda)
    state[0] = state[0]
    # Segunda linha (shift 1 posição à esquerda)
    state[1] = state[1][1:] + state[1][:1]
    # Terceira linha (shift 2 posições à esquerda)
    state[2] = state[2][2:] + state[2][:2]
    # Quarta linha (shift 3 posições à esquerda)
    state[3] = state[3][3:] + state[3][:3]
    return state

# Estado do bloco antes do Shift Rows
state = [
    ['AB', '8B', '89', '35'],
    ['05', '40', '7F', 'F1'],
    ['18', '3F', 'F0', 'FC'],
    ['E4', '4E', '2F', 'C4']
]

# Aplicar Shift Rows
shifted_state = shift_rows(state)

# Exibir o estado após Shift Rows
for row in shifted_state:
    print(' '.join(row))


#Step 5, Round 1: Mix columns
def galois_multiply(a, b):
    """Multiplica dois números no campo de Galois GF(2^8)"""
    result = 0
    while b > 0:
        if b & 1:
            result ^= a
        # Multiplicação por 2 no campo de Galois
        overflow = a & 0x80
        a <<= 1
        if overflow:
            a ^= 0x1B  # Reduzido pelo polinômio irreducível
        b >>= 1
    return result

def mix_columns(state):
    new_state = [[0] * 4 for _ in range(4)]

    for c in range(4):  # Para cada coluna
        new_state[0][c] = galois_multiply(0x02, state[0][c]) ^ galois_multiply(0x03, state[1][c]) ^ state[2][c] ^ state[3][c]
        new_state[1][c] = state[0][c] ^ galois_multiply(0x02, state[1][c]) ^ galois_multiply(0x03, state[2][c]) ^ state[3][c]
        new_state[2][c] = state[0][c] ^ state[1][c] ^ galois_multiply(0x02, state[2][c]) ^ galois_multiply(0x03, state[3][c])
        new_state[3][c] = galois_multiply(0x03, state[0][c]) ^ state[1][c] ^ state[2][c] ^ galois_multiply(0x02, state[3][c])

    return new_state

# Estado do bloco após o Shift Rows
state = [
    [0xAB, 0x8B, 0x98, 0x35],
    [0x40, 0x7F, 0xF1, 0x05],
    [0xF0, 0xFC, 0x18, 0x3F],
    [0xC4, 0xE4, 0x4E, 0x2F]
]

# Aplicar Mix Columns
mixed_state = mix_columns(state)

# Exibir o estado após Mix Columns
for row in mixed_state:
    print(' '.join(format(x, '02X') for x in row))


#Step 6, Round 1: Add round key
def add_round_key(state, round_key):
    """Aplica a operação XOR entre o estado e a chave da rodada"""
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]  # XOR entre estado e round key
    return state

# Estado do bloco após o Mix Columns
mixed_state = [
    [0xB9, 0xE4, 0x47, 0xC5],
    [0x94, 0x8E, 0x20, 0xD6],
    [0x75, 0x07, 0x8B, 0xC6],
    [0x75, 0x51, 0x3F, 0x3B]
]

# Chave da rodada (w4, w5, w6, w7)
round_key = [
    [0xDC, 0x90, 0x37, 0xB0],
    [0x9B, 0x49, 0xDF, 0xE9],
    [0x87, 0xFE, 0x72, 0x3F],
    [0x28, 0x81, 0x15, 0xA7]
]

# Adicionar a chave da rodada ao estado
result_state = add_round_key(mixed_state, round_key)

# Exibir o estado após Add Round Key
for row in result_state:
    print(' '.join(format(x, '02X') for x in row))


#Step 7, Round 2: Substitute bytes

# S-box conforme fornecida

# Estado inicial
state = [
    [0x65, 0x74, 0x70, 0x75],
    [0x0F, 0xC7, 0xFF, 0x3F],
    [0xF2, 0xF9, 0xF9, 0xF9],
    [0x5D, 0xD0, 0x2A, 0x9C]
]

# Substitui bytes
new_state = sub_bytes(state)

# Agora, inverta as linhas e colunas para impressão
print("Novo estado após Substitute Bytes:")
for j in range(4):  # Mudança na ordem para imprimir as colunas
    print(["{:02X}".format(new_state[i][j]) for i in range(4)])  # Mudança na ordem para imprimir as linhas


# Step 8, Round 2: Shift rows
def shift_rows(state):
    """Realiza o deslocamento das linhas do estado."""
    # Primeira linha permanece inalterada
    # Desloca a segunda linha uma posição à esquerda
    state[1] = state[1][1:] + state[1][:1]  # [C6, 99, 70, 92] -> [99, 70, 92, C6]
    # Desloca a terceira linha duas posições à esquerda
    state[2] = state[2][2:] + state[2][:2]  # [99, E5, 51, 16] -> [51, 16, 99, E5]
    # Desloca a quarta linha três posições à esquerda
    state[3] = state[3][3:] + state[3][:3]  # [DE, 9D, 75, 99] -> [99, DE, 9D, 75]
    return state

# Estado após a substituição de bytes (Substitute Bytes)
state = [
    [0x4D, 0x76, 0x89, 0x4C],  # Primeira linha (inalterada)
    [0xC6, 0x99, 0x70, 0x92],  # Segunda linha
    [0x99, 0xE5, 0x51, 0x16],  # Terceira linha
    [0xDE, 0x9D, 0x75, 0x99]   # Quarta linha
]

# Realiza o deslocamento das linhas
new_state = shift_rows(state)

# Imprime o novo estado após Shift Rows
print("Novo estado após Shift Rows:")
for row in new_state:  # Percorre as linhas do estado
    print(["{:02X}".format(byte) for byte in row])  # Imprime os bytes de cada linha



