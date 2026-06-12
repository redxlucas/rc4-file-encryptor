import os
import subprocess
import unittest


class TestRC4(unittest.TestCase):

    def setUp(self):
        self.arquivo_original = "arquivo_de_teste.txt"
        self.arquivo_cifrado = "arquivo_de_teste_cifrado.txt"
        self.arquivo_decifrado = "arquivo_de_teste_decifrado.txt"

        with open(self.arquivo_original, "w", encoding="utf-8") as f:
            f.write("Este é um arquivo de teste para validar o RC4.")

    def tearDown(self):
        for arquivo in [
            self.arquivo_original,
            self.arquivo_cifrado,
            self.arquivo_decifrado,
        ]:
            if os.path.exists(arquivo):
                os.remove(arquivo)

    def test_criptografar_e_decriptografar(self):

        # Equivalente a:
        # python rc4.py arquivo_de_teste.txt 1234 criptografar
        resultado = subprocess.run(
            ["python", "rc4.py", self.arquivo_original, "1234", "criptografar"],
            capture_output=True,
            text=True
        )

        self.assertEqual(resultado.returncode, 0)
        self.assertTrue(os.path.exists(self.arquivo_cifrado))

        # Equivalente a:
        # python rc4.py arquivo_de_teste_cifrado.txt 1234 decriptografar
        resultado = subprocess.run(
            ["python", "rc4.py", self.arquivo_cifrado, "1234", "decriptografar"],
            capture_output=True,
            text=True
        )

        self.assertEqual(resultado.returncode, 0)
        self.assertTrue(os.path.exists(self.arquivo_decifrado))

        # Equivalente a:
        # diff arquivo_de_teste.txt arquivo_de_teste_decifrado.txt
        with open(self.arquivo_original, "rb") as f:
            original = f.read()

        with open(self.arquivo_decifrado, "rb") as f:
            decifrado = f.read()

        self.assertEqual(original, decifrado)


if __name__ == "__main__":
    unittest.main()