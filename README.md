# Training Fighter

MVP mobile-first de treino, evolução, hidratação e consistência. O mesmo código funciona no navegador do iPhone e no desktop.

## Rodar localmente

```bash
npm install
cp .env.example .env
# preencha JWT_SECRET, APP_ENCRYPTION_KEY e DATABASE_URL
npm start
```

O servidor entrega a interface estática e a API no mesmo endereço. Para desenvolvimento visual sem PostgreSQL, também é possível abrir o `index.html` via servidor estático; nesse modo o app usa o armazenamento local do navegador.

## Produção na VPS

O projeto foi preparado para um compose isolado, com dois serviços próprios:

- `app`: interface, autenticação, API OpenAI e OAuth Google Calendar;
- `db`: PostgreSQL dedicado com volume `training_fighter_postgres`.

Variáveis obrigatórias: `POSTGRES_PASSWORD`, `JWT_SECRET` e `APP_ENCRYPTION_KEY`. `OPENAI_API_KEY` fica somente no ambiente do servidor e nunca é enviado ao navegador. Google Calendar exige `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` e uma URI de callback HTTPS autorizada.

## Funcionalidades cloud

- Login com senha armazenada como hash e sessão em cookie HttpOnly.
- Sincronização do estado do treino com PostgreSQL.
- Coach IA via OpenAI Responses API no backend.
- Conexão opcional com Google Calendar por OAuth e leitura/criação de eventos.
- Fallback local para continuar usando o MVP sem servidor.

## Limites conhecidos do MVP

O deploy em IP:porta funciona para validação, mas o uso público no iPhone deve receber um domínio HTTPS e uma URI OAuth Google correspondente. O domínio/DNS ainda precisa ser definido sem alterar os projetos existentes da VPS.
