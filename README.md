# Escola do Futuro — Sistema de Autenticação & Controle de Acesso (EE Antonio Reginato)

Aplicação educacional completa demonstrando **autenticação, geração de JWT e proteção de rotas** com backend FastAPI e páginas HTML integradas.

---

## 🚀 Como Executar

### 1. Instalar as Dependências

```bash
pip install -r requirements.txt
```

> **Compatibilidade:** Totalmente compatível com Python 3.10, 3.11, 3.12 e 3.13 (utiliza `bcrypt` diretamente e o manipulador de `lifespan` moderno do FastAPI).

---

### 2. Iniciar o Servidor FastAPI

```bash
python main.py
```
*(ou: `uvicorn main:app --reload --port 8000`)*

---

### 3. Acessos

- **Portal de Acesso / Login:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Área Restrita (Página Protegida):** [http://127.0.0.1:8000/painel](http://127.0.0.1:8000/painel)
- **Documentação Interativa Swagger:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 🔑 Credenciais Padrão para Teste

Ao iniciar, o banco SQLite (`escola_auth.db`) é criado automaticamente com o administrador padrão:

- **E-mail:** `admin@escola.sp.gov.br`
- **Senha:** `admin123`
- **Perfil:** Gestor / Coordenação

---

## 📡 Endpoints Implementados no FastAPI

| Método | Rota | Descrição | Segurança |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Serve a interface web de login `index.html` | Pública |
| `GET` | `/painel` | Serve a página de área restrita `painel.html` | Pública (validação no client/API) |
| `GET` | `/painel-servidor` | Página restrita bloqueada diretamente pelo servidor | Requer `?token=...` |
| `GET` | `/api/dados-restritos` | Retorna dados confidenciais (notas, turmas, relatórios) | `Bearer <JWT>` (401 se ausente) |
| `GET` | `/auth/health` | Healthcheck de monitoramento do backend | Pública |
| `POST` | `/auth/register` | Criação de nova conta (Nome, Email, Perfil, Senha) | Pública |
| `POST` | `/auth/login` | Login via JSON retornando JWT Token e Perfil | Pública |
| `POST` | `/auth/token` | Login via OAuth2 Form (suporte ao Swagger UI) | Pública |
| `GET` | `/auth/me` | Retorna os dados do usuário autenticado | `Bearer <JWT>` |
| `POST` | `/auth/logout` | Encerra a sessão | `Bearer <JWT>` |

---

## 🎓 Demonstração Pedagógica: Autorizado vs. Acesso Negado

A aplicação foi desenhada especificamente para ilustrar os conceitos de segurança web:

1. **Acesso Negado (HTTP 401 Unauthorized):**
   - Acesse diretamente no navegador: `http://127.0.0.1:8000/painel` sem estar logado.
   - A página detecta a ausência do token, aciona o backend e exibe a tela vermelha de **Acesso Negado**, explicando didaticamente por que a rota foi bloqueada e mostrando o JSON real retornado pelo FastAPI.

2. **Acesso Autorizado (HTTP 200 OK):**
   - Acesse `http://127.0.0.1:8000` e efetue o login.
   - No painel inicial, clique em **"Acessar Área Restrita (Com Permissão Autorizada)"**.
   - A página `painel.html` envia o cabeçalho `Authorization: Bearer <token>`, o FastAPI valida a assinatura criptográfica e desbloqueia os dados sigilosos da escola.

3. **Simulação Interativa de Revogação de Token:**
   - Na página restrita autorizada, clique no botão **"Simular Negação (Apagar Token e Recarregar)"** para ver a mudança de estado em tempo real.
