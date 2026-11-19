# Escola do Futuro — EE Antonio Reginato
## Guia de Execução e Demonstração Pedagógica (Autorização JWT)

---

### 1. Instalar as Dependências

No terminal do projeto (`login`), execute:

```bash
pip install -r requirements.txt
```

> **Atenção (Python 3.12 / 3.13):** O backend foi atualizado para utilizar `bcrypt` diretamente e o handler moderno de `lifespan` do FastAPI, eliminando o erro de versão e o limite de 72 bytes do `passlib`.

---

### 2. Iniciar o Servidor FastAPI

Execute:

```bash
python main.py
```
*(ou: `uvicorn main:app --reload --port 8000`)*

---

### 3. Acessos e Endereços

- **Portal de Login:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Área Restrita (Página Protegida):** [http://127.0.0.1:8000/painel](http://127.0.0.1:8000/painel)
- **Documentação Swagger:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

### 4. Roteiro de Demonstração Pedagógica

#### 🛑 CENÁRIO 1: Acesso Negado (HTTP 401 Não Autorizado)
1. **Sem fazer login**, acesse diretamente no navegador:
   👉 **`http://127.0.0.1:8000/painel`**
   *(ou clique no link vermelho na tela de login: "Testar Acesso Direto sem Login")*.
2. **Resultado pedagógico observado:**
   - Barra superior vermelha.
   - Badge: **HTTP 401 Não Autorizado**.
   - Mensagem explicativa didática informando que o token `Authorization: Bearer` está ausente.
   - Caixa com o JSON real devolvido pelo FastAPI rejeitando o acesso.
3. **Teste direto na API pelo navegador:**
   - Abra a URL da API no navegador: `http://127.0.0.1:8000/api/dados-restritos`
   - O FastAPI responde diretamente:
     ```json
     {
       "detail": "Token de acesso inválido, ausente ou expirado."
     }
     ```

---

#### ✅ CENÁRIO 2: Acesso Autorizado (HTTP 200 OK)
1. Acesse `http://127.0.0.1:8000` e faça login com:
   - **E-mail:** `admin@escola.sp.gov.br`
   - **Senha:** `admin123`
2. No painel inicial do usuário, clique no botão azul:
   👉 **`Acessar Área Restrita (Com Permissão Autorizada)`**
3. **Resultado pedagógico observado:**
   - Barra superior verde/azul.
   - Badge: **HTTP 200 Autorizado**.
   - Os dados confidenciais (notas SARESP, turmas ativas e relatórios sigilosos) são desbloqueados.
   - É exibido o cabeçalho técnico que liberou a requisição: `Authorization: Bearer eyJhbGci...`.

---

#### 🧪 CENÁRIO 3: Simulação de Perda de Permissão em Tempo Real
1. Dentro da página da Área Restrita autorizada, clique no botão:
   👉 **`Simular Negação (Apagar Token e Recarregar)`**
2. A página apaga o token de sessão e faz uma nova requisição à API, mudando instantaneamente para o estado de **Acesso Negado (HTTP 401)** na frente dos alunos/usuários!
