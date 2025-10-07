# Simulações Seguras: Ransomware & Keylogger — Projeto Educacional

> **AVISO DE SEGURANÇA (LEIA ANTES DE EXECUTAR)**
>
> Este repositório contém **simulações educacionais** do comportamento de malware. **NENHUM** código aqui captura teclas em segundo plano, exfiltra dados para a internet ou destrói arquivos do sistema. **Execute os scripts apenas em um ambiente isolado (VM) com snapshot** e usando **somente arquivos de teste** dentro da pasta `./safe_tests/`.

---

## Objetivo

Criar um projeto didático em Python que demonstre, de forma controlada e reversível, os fluxos lógicos de:

- **Ransomware (simulado)** — localizar arquivos em `./safe_tests/`, criar backup, gerar versões cifradas reversíveis com sufixo `.sim`, e gerar nota de "resgate" informativa.
- **Keylogger (simulado)** — processar um arquivo de entrada pré-gravado (`sim_input/typing_sample.txt`) e gerar um log formatado (`keystrokes_simulated.txt`). Produz um arquivo de e-mail **simulado** (`outbox/email_to_send.eml`) em vez de enviar qualquer coisa.

Também inclui um **modelo de relatório** (`REPORT.md`) com reflexões sobre defesa, detecção e resposta.

---

## Estrutura do repositório (sugerida)

```
project-root/
├─ README.md                    # (este arquivo)
├─ helpers.py                   # utilitários (backup, logging, checks)
├─ simulate_ransomware.py       # simulação segura (gera .sim)
├─ simulate_ransomware_decrypt.py # descriptografia de .sim
├─ simulate_keylogger.py        # simulação segura de keylogger (entrada pré-gravada)
├─ REPORT.md                    # relatório modelo
├─ safe_tests/                  # coloque AQUI apenas arquivos de teste
├─ sim_input/                   # coloque typing_sample.txt aqui
└─ outbox/                      # gerado durante a simulação (não envia nada)
```

---

## Regras de segurança (obrigatórias)

1. **Use uma máquina virtual com snapshot** (VirtualBox, VMware, QEMU). Faça snapshot antes de testar.
2. **Isolar rede**: preferível sem conexão com a internet. Se conectar, use rede NAT restrita ou regras que impeçam exfiltração.
3. **Apenas arquivos de teste**: coloque arquivos artificiais em `./safe_tests/` — não use sua pasta de usuário ou unidades montadas.
4. **Não modifique os scripts** para rodar fora da pasta `safe_tests/` sem entender os riscos.
5. **Registro e auditoria**: mantenha `sim_logs.txt` e descreva cada execução no `REPORT.md`.

---

## Como usar — passo a passo

1. Crie pastas e arquivos de teste (dentro do projeto):

```bash
mkdir -p safe_tests sim_input outbox
echo "arquivo de teste 1" > safe_tests/sample1.txt
echo "arquivo de teste 2" > safe_tests/sample2.txt
cat > sim_input/typing_sample.txt <<EOF
user: alice
typed: hello
typed: secret123
EOF
```

2. Crie e ative ambiente virtual (opcional):

```bash
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# Windows PowerShell: use .venv/Scripts/Activate.ps1 (execute no PowerShell)
pip install cryptography
```

3. Executar simulação de ransomware (gera backups e arquivos `.sim`):

```bash
python simulate_ransomware.py --target safe_tests
```

Verifique: `safe_tests/originals_backup/`, `safe_tests/*.sim`, `safe_tests/READ_ME_FOR_RECOVERY.txt`, `sim_logs.txt`.

4. Descriptografar simulados (reverter com chave local):

```bash
python simulate_ransomware_decrypt.py --target safe_tests
```

Verifique: arquivos `*.recovered` gerados.

5. Executar simulação de keylogger (usa `sim_input/typing_sample.txt`):

```bash
python simulate_keylogger.py
```

Verifique: `keystrokes_simulated.txt` e `outbox/email_to_send.eml` (simulação de exfiltração — **não** enviada).

---

## Arquivos de código (copie para seus arquivos .py)

Abaixo estão os scripts seguros incluídos neste repositório. **Revise e entenda** antes de executar.

### helpers.py

```python
# helpers.py
import os
import shutil
from datetime import datetime

LOGFILE = "sim_logs.txt"

def ensure_in_project_dir(path):
    abspath = os.path.abspath(path)
    cwd = os.path.abspath(os.getcwd())
    if not abspath.startswith(cwd):
        raise ValueError("O caminho precisa estar dentro do diretório de trabalho do projeto.")
    return abspath

def safe_list_files(target_dir):
    target_dir = ensure_in_project_dir(target_dir)
    items = []
    for root, dirs, files in os.walk(target_dir):
        for f in files:
            items.append(os.path.join(root, f))
    return items

def make_backup(src_dir, backup_dir_name="originals_backup"):
    src_dir = ensure_in_project_dir(src_dir)
    backup_dir = os.path.join(src_dir, backup_dir_name)
    os.makedirs(backup_dir, exist_ok=True)
    for root, dirs, files in os.walk(src_dir):
        for f in files:
            src_path = os.path.join(root, f)
            if backup_dir in os.path.abspath(src_path):
                continue
            rel_path = os.path.relpath(src_path, src_dir)
            dest_path = os.path.join(backup_dir, rel_path)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            shutil.copy2(src_path, dest_path)
    log(f"Backup criado em: {backup_dir}")
    return backup_dir

def log(msg):
    ts = datetime.utcnow().isoformat() + "Z"
    line = f"[{ts}] {msg}
"
    with open(LOGFILE, "a", encoding="utf-8") as fh:
        fh.write(line)
    print(line.strip())
```

---

### simulate_ransomware.py (SIMULADO — seguro, reversível)

```python
# simulate_ransomware.py
import os
import argparse
from cryptography.fernet import Fernet
from helpers import make_backup, safe_list_files, log

KEYFILE = "sim_key.key"
TARGET_FOLDER = "safe_tests"
BACKUP_NAME = "originals_backup"
RECOVERY_NOTE = "READ_ME_FOR_RECOVERY.txt"

def generate_key(path=KEYFILE):
    if os.path.exists(path):
        log(f"Chave já existe em {path}")
        with open(path, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(path, "wb") as f:
        f.write(key)
    log(f"Chave gerada em {path}")
    return key

def load_key(path=KEYFILE):
    with open(path, "rb") as f:
        return f.read()

def is_in_backup(path, src_dir):
    return os.path.abspath(path).startswith(os.path.abspath(os.path.join(src_dir, BACKUP_NAME)))

def simulate_encrypt_folder(folder, key):
    f = Fernet(key)
    files = safe_list_files(folder)
    for filepath in files:
        if is_in_backup(filepath, folder): 
            continue
        if filepath.endswith(".sim"):
            continue
        if os.path.basename(filepath) == RECOVERY_NOTE:
            continue
        try:
            with open(filepath, "rb") as fh:
                data = fh.read()
            token = f.encrypt(data)
            out_path = filepath + ".sim"
            with open(out_path, "wb") as outfh:
                outfh.write(token)
            log(f"Arquivo simulado cifrado gerado: {out_path}")
        except Exception as exc:
            log(f"Erro ao processar {filepath}: {exc}")

def write_recovery_note(folder):
    note_path = os.path.join(folder, RECOVERY_NOTE)
    text = (
        "ESTE É UM AMBIENTE DE TESTE

"
        "Os arquivos com sufixo '.sim' foram gerados por uma simulação educacional.
"
        "Para recuperar os dados, utilize o script 'simulate_ransomware_decrypt.py' "
        "com a chave local presente no repositório (simulate project file).

"
        "NÃO ENTRE em pânico — isto é uma simulação. Restaure snapshots se algo inesperado ocorrer.
"
    )
    with open(note_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    log(f"Nota de recuperação escrita: {note_path}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default=TARGET_FOLDER, help="Pasta alvo (default: safe_tests)")
    parser.add_argument("--regenerate-key", action="store_true", help="Gerar nova chave (substitui se existir)")
    args = parser.parse_args()

    target = args.target
    if os.path.abspath(target) == os.path.abspath("/"):
        raise SystemExit("Target inválido.")
    make_backup(target, )
    if args.regenerate_key and os.path.exists(KEYFILE):
        os.remove(KEYFILE)
    key = generate_key(KEYFILE)
    simulate_encrypt_folder(target, key)
    write_recovery_note(target)
    log("Simulação concluída.")

if __name__ == "__main__":
    main()
```

---

### simulate_ransomware_decrypt.py

```python
# simulate_ransomware_decrypt.py
import os
import argparse
from cryptography.fernet import Fernet
from helpers import safe_list_files, log

KEYFILE = "sim_key.key"

def load_key(path=KEYFILE):
    if not os.path.exists(path):
        raise FileNotFoundError("Arquivo de chave não encontrado. Execute simulate_ransomware.py primeiro.")
    with open(path, "rb") as f:
        return f.read()

def decrypt_sim_files(target, key):
    f = Fernet(key)
    files = safe_list_files(target)
    for filepath in files:
        if not filepath.endswith(".sim"):
            continue
        try:
            with open(filepath, "rb") as fh:
                token = fh.read()
            data = f.decrypt(token)
            out_path = filepath.replace(".sim", ".recovered")
            with open(out_path, "wb") as outfh:
                outfh.write(data)
            log(f"Arquivo recuperado: {out_path}")
        except Exception as exc:
            log(f"Erro ao descriptografar {filepath}: {exc}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="safe_tests", help="Pasta alvo (default: safe_tests)")
    args = parser.parse_args()
    key = load_key(KEYFILE)
    decrypt_sim_files(args.target, key)
    log("Descriptografia concluída.")

if __name__ == "__main__":
    main()
```

---

### simulate_keylogger.py (SIMULADO — sem hook de teclado)

```python
# simulate_keylogger.py
import os
from datetime import datetime
from helpers import log

INPUT_FILE = os.path.join("sim_input", "typing_sample.txt")
OUTPUT_FILE = "keystrokes_simulated.txt"
OUTBOX_DIR = "outbox"
EML_FILE = os.path.join(OUTBOX_DIR, "email_to_send.eml")

def read_input_sim():
    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(f"Arquivo de simulação não encontrado: {INPUT_FILE}")
    with open(INPUT_FILE, "r", encoding="utf-8") as fh:
        lines = fh.readlines()
    return [l.rstrip("
") for l in lines]

def create_keystroke_log(events):
    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        for ev in events:
            ts = datetime.utcnow().isoformat() + "Z"
            fh.write(f"[{ts}] {ev}
")
    log(f"Keystrokes simulados escritos em {OUTPUT_FILE}")

def create_outbox_sim():
    os.makedirs(OUTBOX_DIR, exist_ok=True)
    body = (
        "From: simulated@example.com
"
        "To: attacker@example.com
"
        "Subject: simulated exfiltration

"
        "ANEXO: keystrokes_simulated.txt

"
        "Observação: este arquivo está na pasta outbox e NÃO foi enviado.
"
    )
    with open(EML_FILE, "w", encoding="utf-8") as fh:
        fh.write(body)
    log(f"Arquivo de e-mail simulado criado em {EML_FILE}")

def main():
    events = read_input_sim()
    create_keystroke_log(events)
    create_outbox_sim()
    log("Simulação de keylogger concluída.")

if __name__ == "__main__":
    main()
```

---

## Conteúdo de exemplo para `sim_input/typing_sample.txt`

```
login: alice
password: P@ssw0rd!
opened_file: notes.txt
typed: hello world
```

---

## Modelo de `REPORT.md` (preencha com observações reais de seus testes)

```markdown
# REPORT — Simulações: Ransomware e Keylogger (educacional)

## Objetivo
Descrever o ambiente, o que foi simulado, observações e medidas defensivas.

## Ambiente de teste
- VM: VirtualBox (exemplo)
- Sistema: (ex.: Ubuntu 22.04)
- Snapshots: criado snapshot "pre-sim"
- Rede: isolada / sem internet

## Procedimentos executados
1. Criado pasta `safe_tests/` com arquivos de teste.
2. Executado `python simulate_ransomware.py` — backup gerado e arquivos `.sim` criados.
3. Executado `python simulate_ransomware_decrypt.py` — arquivos `*.recovered` gerados.
4. Preenchido `sim_input/typing_sample.txt` e executado `python simulate_keylogger.py`.

## Observações técnicas
- O ransomware simulado utiliza cifra simétrica (Fernet) e não sobrescreve originais.
- O keylogger simulado lê entrada pré-gravada e cria um arquivo que imita saída de keylogger.
- Simulação de exfiltração: arquivo de e-mail gerado em `outbox/` — sem envio real.

## Medidas de defesa (resumo)
- Backups regulares (3-2-1), snapshots testados.
- Least Privilege: usuários sem direitos de escrita em diretórios críticos.
- EDR/Antivírus: monitorar criação massiva de arquivos, extensões novas, conexões de saída suspeitas.
- Segmentação de rede, whitelisting de execução (AppLocker, SELinux).
- Treinamento anti-phishing e políticas de senha + MFA.

## Conclusão
Este exercício demonstrou os fluxos lógicos de ataques comuns de forma segura e reversível.
```

---

## Dicas para publicação no GitHub

1. Inclua este `README.md` com o aviso de segurança no topo.
2. **NÃO** inclua dados reais, senhas, ou chaves privadas.
3. Se publicar publicamente, deixe claro no `README.md` que *isto é material educacional* e que os scripts só operam em `./safe_tests/`.
4. Use um `LICENSE` apropriado (MIT, Apache, etc.) se desejar.

Para inicializar um repositório local e enviar ao GitHub:

```bash
git init
git add .
git commit -m "Simulações seguras: Ransomware e Keylogger (educacional)"
# crie repositório no GitHub e depois:
# git remote add origin git@github.com:SEU_USUARIO/NOME_REPO.git
# git branch -M main
# git push -u origin main
```

---

## Perguntas comuns

- **Posso modificar os scripts para apontar para outros diretórios?**
  Sim — mas apenas em VMs isoladas e com extremo cuidado. Recomendo testar primeiro em `safe_tests/`.

- **Posso adicionar envio por e-mail real para testar detecção de DLP/EDR?**
  Se for necessário para um teste autorizado em laboratório, configure uma rede isolada e um servidor de teste; **nunca** envie dados reais para terceiros.

---

## Conclusão
Este README consolida todo o material necessário para executar as simulações de forma segura e educativa.
