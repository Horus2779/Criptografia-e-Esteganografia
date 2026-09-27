# Laboratório Prático de Criptografia e Esteganografia

Projeto acadêmico para a disciplina **Confiabilidade, Segurança de Sistemas e Ergonomia**.

## Estrutura

- `src/main.py` — implementação dos três módulos.
- `images/imagem_original.png` — imagem usada no experimento.
- `images/imagem_esteganografada.png` — imagem após a inserção da mensagem.
- `requirements.txt` — dependências Python.
- `relatorio.docx` — relatório da atividade.

## Como executar

```bash
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Instale as dependências:

```bash
pip install -r requirements.txt
```

Execute:

```bash
python src/main.py
```

## Observações de segurança

- O módulo de autenticação não armazena a senha original.
- O salt é gerado aleatoriamente para cada cadastro.
- O AES utiliza uma chave de 256 bits e modo GCM, que fornece confidencialidade e autenticação do ciphertext.
- A esteganografia LSB altera somente o bit menos significativo dos canais RGB utilizados.
- O projeto é acadêmico e não deve ser usado diretamente como sistema de autenticação ou armazenamento financeiro em produção sem revisão de segurança.
