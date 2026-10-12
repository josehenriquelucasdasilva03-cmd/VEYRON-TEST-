# Login e OpenAI na Veyro IA

Esta branch adiciona uma implementação de teste, sem alterar o site oficial.

Fluxo: criar conta com nome de usuário, senha (mínimo de 12 caracteres) e código privado de instalação; entrar; informar a chave OpenAI; usar o chat.

Backend: o arquivo worker/worker.js roda num Cloudflare Worker separado, conectado ao banco Cloudflare D1 pelo binding DB. Execute worker/schema.sql no D1 antes do primeiro acesso.

Configure no Worker os Secrets VEYRO_SETUP_CODE (valor aleatório de pelo menos 20 caracteres) e VEYRO_MASTER_KEY (32 bytes aleatórios em Base64). Configure a variável VEYRO_ALLOWED_ORIGIN com a origem exata do site de teste, por exemplo https://josehenriquelucasdasilva03-cmd.github.io. Opcionalmente configure OPENAI_MODEL (padrão gpt-4.1-mini).

Depois de publicar o Worker por HTTPS, edite runtime-config.js SOMENTE NA BRANCH DE TESTE e informe apiBase com o endereço real desse Worker. Enquanto apiBase estiver vazio, a tela não enviará nenhuma senha nem chave e funcionará apenas como prévia visual.

A senha é derivada com PBKDF2-SHA256; sessões expiram em oito horas; a chave OpenAI fica criptografada com AES-256-GCM vinculada à conta. O endpoint de chat exige token, tem limite de 10 mensagens por minuto e restringe o tamanho das requisições. Nenhuma chave OpenAI é publicada no GitHub.

ATENÇÃO: GitHub Pages é um host estático; a segurança real depende do Worker implantado. Não insira sua chave real até ter confirmado a origem e HTTPS do seu Worker. A API tem cobrança independente do ChatGPT. O código de teste ainda precisa de validação ponta a ponta, controle de custos e limpeza periódica de sessões/rate limits antes de ser usado com terceiros.


## Segurança e demonstração (11/10/2026)

- O cadastro inicial é fechado após a primeira conta. A rota `/setup` permanece para login, enquanto `/chat` mostra um chat demonstrativo autenticado.
- O endpoint `POST /api/chat/demo` retorna texto fixo por SSE. Não utiliza modelo de IA nem gera gastos com tokens.
- O endpoint real `POST /api/chat` está **desabilitado por padrão** e só pode chamar a OpenAI se `VEYRO_CHAT_ENABLED=true` for configurado explicitamente. A configuração atual **não habilita** essa variável.
- Mesmo se habilitado futuramente, aplica limites básicos de 10 chamadas/minuto e 20 chamadas/dia por usuário, além de 500 tokens de saída. Isso **não** equivale a teto financeiro rígido. Exige aprovação de custos, limite de gastos no provedor e testes antes de habilitar.
- O site em GitHub Pages permanece inalterado na branch principal. `runtime-config.js` na branch experimental usa `useLiveChat:false`.
- O modo demonstrativo não representa uma resposta real do modelo. Testar a experiência completa requer ambiente de prévia para a branch experimental e validação de sessão, SSE, logout e limites.


## API gratuita Qwen Workers AI (preparada, bloqueada por padrão)

Modelo: `@cf/qwen/qwen3-30b-a3b-fp8` via vinculação de tipo `ai` denominada `AI` no Worker `veyro-auth-test`. A rota autenticada `POST /api/chat/qwen` responde em formato SSE compatível com a interface. `GET /api/qwen/status` informa limites sem dados sensíveis.

**Importante:** `VEYRO_QWEN_ENABLED` fica ausente/desligada até verificar no painel Cloudflare que a conta está no plano Workers Free e não há faturamento por excedente. Não configure como `true` sem essa verificação e supervisão. O plano Workers Paid pode faturar acima dos 10.000 Neurons grátis; os limites do aplicativo não substituem controles da plataforma. Nenhuma chave OpenAI é necessária para o Workers AI.

Limites preventivos: até 20 mensagens reais/dia por usuário, 100/dia compartilhadas, 3/minuto, 600 caracteres por pergunta, 4 mensagens curtas de histórico e 256 tokens de saída; contagem diária por UTC, com reserva atômica em D1. Esses limites são **por mensagens**, não garantem uma quantidade exata de Neurons ou custo zero se outros serviços compartilharem a conta. A franquia gratuita do Workers AI é de 10.000 Neurons/dia e reseta a 00:00 UTC.

Migration incremental: criar `ai_daily_limits` conforme `worker/schema.sql` sem apagar as demais tabelas. O endpoint demonstrativo continua funcionando sem Workers AI. O site oficial segue sem alterações e a branch permanece em PR de rascunho.
