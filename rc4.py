import sys
import os
import hashlib
import secrets

SALT_SIZE = 16
KEY_SIZE = 32
PBKDF2_ITER = 200_000

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


def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        hash_name = 'sha256',
        password = password.encode('utf-8'),
        salt = salt,
        iterations = PBKDF2_ITER,
        dklen = KEY_SIZE
    )

def criptografar(caminho_entrada: str, senha: str) -> str:
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


def decriptografar(caminho_entrada: str, senha: str) -> str:
    with open(caminho_entrada, 'rb') as f:
        conteudo = f.read()

    if len(conteudo) < SALT_SIZE:
        raise ValueError("Arquivo cifrado inválido ou corrompido (muito pequeno).")

    salt = conteudo[:SALT_SIZE]
    dados_cifrados = conteudo[SALT_SIZE:]

    chave = derive_key(senha, salt)

    dados_claros = rc4_process(chave, dados_cifrados)

    nome = os.path.basename(caminho_entrada)
    diretorio = os.path.dirname(caminho_entrada)

    if nome.endswith("_cifrado.txt"):
        nome_saida = nome[: -len("_cifrado.txt")] + "_decifrado.txt"
    else:
        base, ext = os.path.splitext(caminho_entrada)
        nome_saida = f"{base}_decifrado{ext}"

    caminho_saida = os.path.join(diretorio, nome_saida) if diretorio else nome_saida

    with open(caminho_saida, 'wb') as f:
        f.write(dados_claros)

    return caminho_saida

def validar_entradas(args: list) -> tuple:
    if len(args) != 3:
        print("Erro: número de argumentos inválido.")
        print("Uso: python3 cripto.py <arquivo.txt> <chave> <criptografar|decriptografar>")
        sys.exit(1)

    caminho, senha, operacao = args

    operacao = operacao.lower()
    if operacao not in ("criptografar", "decriptografar"):
        print(f"Erro: operação '{operacao}' inválida. Use 'criptografar' ou 'decriptografar'.")
        sys.exit(1)

    if not os.path.isfile(caminho):
        print(f"Erro: arquivo '{caminho}' não encontrado.")
        sys.exit(1)

    if not caminho.lower().endswith(".txt"):
        print(f"Erro: o arquivo deve ter extensão .txt (recebido: '{caminho}').")
        sys.exit(1)

    if operacao == "decriptografar" and not os.path.basename(caminho).endswith("_cifrado.txt"):
        print(f"Erro: para decriptografar, o arquivo deve terminar em '_cifrado.txt' (recebido: '{caminho}').")
        sys.exit(1)

    if not senha:
        print("Erro: a chave não pode ser vazia.")
        sys.exit(1)

    return caminho, senha, operacao

def main():
    caminho, senha, operacao = validar_entradas(sys.argv[1:])

    try:
        if operacao == "criptografar":
            saida = criptografar(caminho, senha)
            print(f"Arquivo cifrado gerado: {saida}")
        else:
            saida = decriptografar(caminho, senha)
            print(f"Arquivo decifrado gerado: {saida}")
    except PermissionError:
        print(f"Erro: sem permissão para ler/escrever o arquivo '{caminho}'.")
        sys.exit(1)
    except OSError as e:
        print(f"Erro de I/O: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()