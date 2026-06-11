import sys
import os
import hashlib
import secrets

def ksa(key: bytes) -> list:
    key_len = len(key)

    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]
    return S
 
 
def prga(S: list, data_len: int):
    i = 0
    j = 0
    for _ in range(data_len):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        yield S[(S[i] + S[j]) % 256]
 
 
def rc4_process(key: bytes, data: bytes) -> bytes:
    S = ksa(key)
    keystream = prga(S, len(data))
    return bytes(b ^ k for b, k in zip(data, keystream))
 
SALT_SIZE    = 16
KEY_SIZE     = 32
PBKDF2_ITER  = 200_000
 
 
def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        hash_name   = 'sha256',
        password    = password.encode('utf-8'),
        salt        = salt,
        iterations  = PBKDF2_ITER,
        dklen       = KEY_SIZE
    )

def encrypt(caminho_entrada: str, senha: str) -> str:
    with open(caminho_entrada, 'rb') as f:
        dados = f.read()
 
    salt = secrets.token_bytes(SALT_SIZE)
    chave = derive_key(senha, salt)
 
    dados_cifrados = rc4_process(chave, dados)
 
    base, ext = os.path.splitext(caminho_entrada)
    caminho_saida = f"{base}_cifrado{ext}"
 
    with open(caminho_saida, 'wb') as f:
        f.write(salt + dados_cifrados)
 
    return caminho_saida

def validate_entries(args: list):
    if len(args) != 3:
        print("Erro: número de argumentos inválido.")
        print("Uso: python rc4.py <arquivo.txt> <chave> <criptografar|decriptografar>")
        sys.exit(1)

    file_path, password, operation = args

    operation = operation.lower()
    if operation not in ['criptografar', 'decriptografar']:
        print(f"Erro: operação '{operation}' inválida. Use 'criptografar' ou 'decriptografar'.")
        sys.exit(1)

    if not file_path.lower().endswith(".txt"):
        print(f"Erro: o arquivo deve ter extensão .txt (recebido: '{file_path}').")
        sys.exit(1)

    if operation == "decriptografar" and not os.path.basename(file_path).endswith("_cifrado.txt"):
        print(f"Erro: para decriptografar, o arquivo deve terminar em '_cifrado.txt' (recebido: '{file_path}').")
        sys.exit(1)

    if not password:
        print("Erro: a chave não pode ser vazia.")
        sys.exit(1)

    return file_path, password, operation

def main():
    file_path, password, operation = validate_entries(sys.argv[1:])

    try:
        if operation == 'decriptografar':
            output = encrypt(file_path, password)
            print(f"Arquivo cifrado gerado: {output}")

    except PermissionError:
        print(f"Erro: sem permissão para ler/escrever o arquivo '{file_path}'.")
        sys.exit(1)
    except OSError as e:
        print(f"Erro de I/O: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()