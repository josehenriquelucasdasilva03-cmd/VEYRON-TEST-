# Veyro IA | Interface completa de prévia

URL: https://veyro-auth-test.josehenriquelucasdasilva03.workers.dev/preview

- Usa a arquitetura e nomes dos recursos do site de GitHub Pages (conversa, imagens, vídeos, agentes e projetos); visual redesenhado como aplicativo completo, no estilo preto/branco/dourado com fundo de planeta e movimentos 3D CSS.
- O login usa as mesmas rotas protegidas D1 da conta já criada, diretamente na página, sem depender de sessão de outras abas.
- Conversas ficam apenas no sessionStorage do navegador por usuário; não são sincronizadas entre dispositivos nem persistidas no servidor.
- Chat funciona no modo demonstrativo sem IA. O modo Qwen só aparece habilitado após a variável segura VEYRO_QWEN_ENABLED=true e vinculação AI; não ativar antes de confirmar plano Workers Free e condições de faturamento.
- Imagens, vídeos, agentes e projetos são áreas visuais identificadas como em desenvolvimento; sem geração real, sem APIs pagas.
- Esta é uma prévia de teste isolada. Não altera o site oficial de GitHub Pages, nem faz merge do PR #1.
- Testar manualmente login, novo chat, menu no celular, streaming, histórico na aba, logout e bloquear acesso sem token. Usar sem enviar credenciais ao chat.
