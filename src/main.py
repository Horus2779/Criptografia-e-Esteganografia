"""
Laboratório Prático de Criptografia e Esteganografia
Disciplina: Confiabilidade, Segurança de Sistemas e Ergonomia

Dependências:
    pip install cryptography pillow

Execução:
    python main.py
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image


# ============================================================
# MÓDULO 1 - HASHING COM SALT
# ============================================================

def cadastrar_usuario(usuario: str, senha: str) -> dict:
    """Simula um cadastro sem armazenar a senha em texto puro."""
    salt = secrets.token_bytes(16)

    # PBKDF2-HMAC-SHA256 aplica SHA-256 repetidamente com salt.
    hash_senha = hashlib.pbkdf2_hmac(
        "sha256",
        senha.encode("utf-8"),
        salt,
        600_000,
    )

    return {
        "usuario": usuario,
        "salt": base64.b64encode(salt).decode("ascii"),
        "senha_hash": base64.b64encode(hash_senha).decode("ascii"),
        "iteracoes": 600_000,
        # A senha original NÃO é armazenada.
    }


def verificar_senha(senha_informada: str, registro: dict) -> bool:
    salt = base64.b64decode(registro["salt"])
    esperado = base64.b64decode(registro["senha_hash"])

    calculado = hashlib.pbkdf2_hmac(
        "sha256",
        senha_informada.encode("utf-8"),
        salt,
        registro["iteracoes"],
    )

    return hmac.compare_digest(calculado, esperado)


# ============================================================
# MÓDULO 2 - CRIPTOGRAFIA SIMÉTRICA AES-256-GCM
# ============================================================

def cifrar_dados(texto: str, chave: bytes) -> str:
    """Cifra texto com AES-256-GCM e retorna Base64."""
    if len(chave) != 32:
        raise ValueError("A chave deve possuir 32 bytes (AES-256).")

    nonce = secrets.token_bytes(12)
    cifrado = AESGCM(chave).encrypt(nonce, texto.encode("utf-8"), None)

    # Guardamos nonce + ciphertext em uma única string.
    return base64.b64encode(nonce + cifrado).decode("ascii")


def decifrar_dados(cifrado_b64: str, chave: bytes) -> str:
    if len(chave) != 32:
        raise ValueError("A chave deve possuir 32 bytes (AES-256).")

    dados = base64.b64decode(cifrado_b64)
    nonce, ciphertext = dados[:12], dados[12:]

    texto = AESGCM(chave).decrypt(nonce, ciphertext, None)
    return texto.decode("utf-8")


# ============================================================
# MÓDULO 3 - ESTEGANOGRAFIA LSB EM PNG
# ============================================================

def _bytes_para_bits(dados: bytes):
    for byte in dados:
        for deslocamento in range(7, -1, -1):
            yield (byte >> deslocamento) & 1


def _bits_para_bytes(bits):
    resultado = bytearray()
    for i in range(0, len(bits), 8):
        bloco = bits[i:i + 8]
        if len(bloco) < 8:
            break
        valor = 0
        for bit in bloco:
            valor = (valor << 1) | bit
        resultado.append(valor)
    return bytes(resultado)


def ocultar_mensagem(entrada: str, saida: str, mensagem: str) -> None:
    """Oculta uma mensagem nos LSBs dos canais RGB de um PNG."""
    imagem = Image.open(entrada).convert("RGB")
    pixels = list(imagem.getdata())

    payload = mensagem.encode("utf-8")
    # Prefixo de 4 bytes permite saber exatamente o tamanho da mensagem.
    dados = len(payload).to_bytes(4, "big") + payload
    bits = list(_bytes_para_bits(dados))

    capacidade = len(pixels) * 3
    if len(bits) > capacidade:
        raise ValueError("Mensagem maior que a capacidade da imagem.")

    novos_pixels = []
    indice_bit = 0

    for r, g, b in pixels:
        canais = [r, g, b]
        for i in range(3):
            if indice_bit < len(bits):
                canais[i] = (canais[i] & 0xFE) | bits[indice_bit]
                indice_bit += 1
        novos_pixels.append(tuple(canais))

    imagem.putdata(novos_pixels)
    imagem.save(saida, "PNG")


def extrair_mensagem(arquivo: str) -> str:
    imagem = Image.open(arquivo).convert("RGB")
    pixels = list(imagem.getdata())

    bits = []
    for r, g, b in pixels:
        bits.extend([r & 1, g & 1, b & 1])

    tamanho = int.from_bytes(_bits_para_bytes(bits[:32]), "big")
    total_bits = 32 + tamanho * 8

    if total_bits > len(bits):
        raise ValueError("Payload inválido ou imagem sem mensagem.")

    payload = _bits_para_bytes(bits[32:total_bits])
    return payload.decode("utf-8")


# ============================================================
# DEMONSTRAÇÃO
# ============================================================

def main():
    pasta = Path(__file__).resolve().parent.parent
    imagem_original = pasta / "images" / "imagem_original.png"
    imagem_esteganografada = pasta / "images" / "imagem_esteganografada.png"

    print("=" * 70)
    print("LABORATÓRIO PRÁTICO DE CRIPTOGRAFIA E ESTEGANOGRAFIA")
    print("=" * 70)

    # 1. Hashing
    registro = cadastrar_usuario("aluno", "Senha-Forte-2026!")
    print("\n[1] HASHING + SALT")
    print("Usuário:", registro["usuario"])
    print("Salt:", registro["salt"])
    print("Hash:", registro["senha_hash"])
    print("Senha correta:", verificar_senha("Senha-Forte-2026!", registro))
    print("Senha incorreta:", verificar_senha("senha-errada", registro))

    # 2. AES
    chave = AESGCM.generate_key(bit_length=256)
    texto = "Conta: 12345 | Saldo: R$ 15.750,80 | Transação: R$ 850,00"
    cifrado = cifrar_dados(texto, chave)
    decifrado = decifrar_dados(cifrado, chave)

    print("\n[2] AES-256-GCM")
    print("Texto original:", texto)
    print("Texto cifrado (Base64):", cifrado)
    print("Texto decifrado:", decifrado)
    print("Integridade:", texto == decifrado)

    # 3. Esteganografia
    mensagem = "Informação confidencial: trabalho acadêmico de segurança."
    ocultar_mensagem(str(imagem_original), str(imagem_esteganografada), mensagem)
    extraida = extrair_mensagem(str(imagem_esteganografada))

    print("\n[3] ESTEGANOGRAFIA LSB")
    print("Mensagem original:", mensagem)
    print("Mensagem extraída:", extraida)
    print("Extração correta:", mensagem == extraida)
    print("\nArquivos gerados:")
    print(imagem_esteganografada)


if __name__ == "__main__":
    main()
