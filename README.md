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

Variáveis obrigatórias: `POSTGRES_PASSWORD`, `JWT_SECRET` e `APP_ENCRYPTION_KEY`. `OPENAI_API_KEY` fica somente no ambiente do servidor e nunca é enviado ao navegador. O login é somente com Google: no primeiro acesso a conta é criada automaticamente e a autorização do Google Calendar acontece no mesmo fluxo. Isso não usa Clerk/Auth0; a sessão, o banco e os tokens criptografados ficam na VPS.

## Funcionalidades cloud

- Login Google-only com sessão em cookie HttpOnly e criação automática da conta.
- Sincronização do estado do treino com PostgreSQL.
- Coach IA via OpenAI Responses API no backend.
- Google Calendar conectado por OAuth com escopo de leitura/criação de eventos e refresh token criptografado no banco.
- Fallback visual local para desenvolvimento; o acesso publicado exige o backend da VPS.

## Limites conhecidos do MVP

O deploy em IP:porta funciona para validação, mas o uso público no iPhone precisa de um domínio HTTPS. No Google Cloud, crie um cliente OAuth do tipo Web application, habilite a Google Calendar API e cadastre exatamente `https://SEU_DOMINIO/api/google/callback` como URI de redirecionamento autorizado. Os três valores (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` e `GOOGLE_REDIRECT_URI`) entram somente nas variáveis da VPS.
