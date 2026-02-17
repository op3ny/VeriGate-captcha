# 🛡️ VeriGate CAPTCHA

Documentação oficial do sistema de CAPTCHA VeriGate

Um sistema próprio, independente, validado via backend-to-backend — sem depender de Google reCAPTCHA ou serviços externos.

---

## 📌 O que é o VeriGate?

O **VeriGate** é um sistema de verificação anti-bot baseado em desafio interativo no frontend e validação segura no backend.

Ele funciona em três partes:

1. **Frontend (captcha-client.js + style.css)** → Renderiza e executa o desafio.
2. **Servidor VeriGate (server.js)** → Gera, armazena e valida tokens.
3. **Backend da aplicação protegida** → Consulta o servidor do VeriGate para validar o token antes de permitir acesso ao endpoint protegido.

---

## 🧠 Como Funciona (Visão Geral)

### 🔁 Fluxo completo

1. Usuário acessa uma página protegida.
2. O CAPTCHA é renderizado pelo `captcha-client.js`.
3. O usuário resolve o desafio.
4. O frontend recebe um **token de verificação**.
5. Esse token é enviado junto com a requisição ao backend da aplicação.
6. O backend da aplicação envia o token para o backend do **VeriGate**.
7. O VeriGate valida o token.
8. Se válido → acesso permitido.
9. Se inválido → acesso negado.

---

# 🏗️ Estrutura do Projeto

```
verigate/
 ├── server.js
 ├── captcha-client.js
 ├── style.css
```

---

# 🚀 Como Rodar o VeriGate

## 1️⃣ Pré-requisitos

* Node.js 18+
* ES Modules habilitado
* Dependências necessárias (se houver no `server.js`)

## 2️⃣ Instalar dependências

Se houver `package.json`:

```bash
npm install
```

Caso contrário, instale manualmente o que for usado no `server.js`.

## 3️⃣ Iniciar o servidor

```bash
node server.js
```

O servidor iniciará em uma porta definida dentro do `server.js`.

---

# 🖥️ Parte Frontend – Como Usar o CAPTCHA

## 1️⃣ Importar os arquivos

No seu HTML:

```html
<link rel="stylesheet" href="/style.css">
<script src="/captcha-client.js" defer></script>
```

---

## 2️⃣ Criar o container do captcha

```html
<div id="verigate-captcha"></div>
```

O JavaScript irá renderizar o CAPTCHA dentro desse container.

---

# 🎨 Sobre o `style.css`

O CSS define a estrutura visual do captcha, incluindo:

```css
.captcha-container {
    position: relative;
    user-select: none;
}
```

Isso impede:

* Seleção de texto
* Interações automatizadas simples
* Copiar conteúdo facilmente

O container usa `position: relative` para permitir sobreposição de elementos do desafio (como camadas, canvas ou elementos dinâmicos).

---

# 🧩 Como Funciona o `captcha-client.js`

O arquivo `captcha-client.js` é responsável por:

### ✔️ Renderizar o desafio

Cria dinamicamente os elementos HTML dentro do container.

### ✔️ Controlar a interação

Escuta eventos como:

* click
* drag
* movimentação
* tempo de resposta

### ✔️ Gerar o token

Após o desafio ser resolvido corretamente:

* O cliente recebe um **token único**
* Esse token representa que o desafio foi completado

### ✔️ Disponibilizar o token

Normalmente:

* O token é armazenado em variável global
* Ou inserido automaticamente em um `<input hidden>`

Exemplo típico:

```html
<input type="hidden" name="captchaToken" id="captchaToken">
```

O JS preenche esse campo quando o captcha é resolvido.

---

# 🔐 Parte Backend – Como Validar o Token

Aqui está o ponto MAIS IMPORTANTE.

O token gerado no frontend **não deve ser confiado diretamente**.

Quando o usuário enviar um formulário ou acessar um endpoint protegido:

## Backend da aplicação:

```js
import fetch from "node-fetch";

const response = await fetch("https://verigate-server/verify", {
    method: "POST",
    headers: {
        "Content-Type": "application/json"
    },
    body: JSON.stringify({
        token: captchaToken
    })
});

const result = await response.json();

if (!result.success) {
    return res.status(403).json({ error: "Captcha inválido" });
}
```

---

# 🔎 O que o `server.js` faz

O servidor do VeriGate é responsável por:

### 🧠 Gerar desafios

Cria um desafio único por sessão.

### 🎟️ Emitir tokens

Após resolução correta:

* Gera token único
* Pode armazenar em memória (Map, Redis, etc)
* Associa token com validade

### ⏳ Expiração

Tokens normalmente:

* Expiram após X minutos
* São single-use (uso único)

### 🔎 Endpoint de verificação

Exemplo típico:

```
POST /verify
```

Recebe:

```json
{
  "token": "abc123"
}
```

Retorna:

```json
{
  "success": true
}
```

---

# 🔐 Segurança Implementada

O VeriGate implementa:

* Tokens únicos
* Validade limitada
* Verificação server-to-server
* Não expõe lógica de validação no frontend
* Evita confiar apenas em JS

---

# 🧱 Como Implementar em Uma Aplicação

## 🪜 Passo a passo

### 1️⃣ Subir o servidor VeriGate

```bash
node server.js
```

---

### 2️⃣ Incluir captcha-client.js no frontend

```html
<script src="https://seu-verigate/captcha-client.js"></script>
```

---

### 3️⃣ Adicionar container

```html
<div id="verigate-captcha"></div>
```

---

### 4️⃣ No backend da aplicação protegida

Antes de permitir:

```js
POST /login
POST /register
POST /api/private
```

Valide:

```js
await validarCaptcha(token)
```

---

# 📡 Arquitetura Recomendada

```
[ Usuário ]
     ↓
[ Frontend com captcha-client.js ]
     ↓ (token)
[ Backend da Aplicação ]
     ↓ (server-to-server)
[ Servidor VeriGate ]
     ↓
 Validação
```

---

# 📦 Nome do Sistema

**VeriGate CAPTCHA**

> Sistema proprietário de verificação anti-automação com validação backend-to-backend.

---

# 🧪 Exemplos de Uso

### 🔑 Proteger login

```js
if (!captchaValido) {
    return res.status(403).send("Verificação obrigatória");
}
```

---

### 📝 Proteger formulário

Adicionar o token junto no body:

```js
{
  email,
  password,
  captchaToken
}
```

---

# 🛠️ Possíveis Melhorias Futuras

* Rate limiting por IP
* Assinatura JWT no token
* Armazenamento Redis
* Score de risco
* Detecção comportamental

---

# 📚 Resumo

O VeriGate é:

* Independente
* Seguro
* Validado via backend
* Customizável
* Ideal para aplicações Node.js

---

# Finalização

Esse projeto foi criado pela [Thaís](https://github.com/op3ny), e verifique a licença antes de usar (Este projeto é Open Source).
