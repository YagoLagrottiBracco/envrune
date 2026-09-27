# Envrune — Design da v1

## Objetivo

Envrune e um CLI open-source, Linux-first e local-first para que desenvolvedores armazenem um secret uma unica vez e o associem, por referencia, a variaveis de ambiente de varios projetos. Ele elimina a necessidade de manter valores reais em `.env` durante o desenvolvimento normal.

O comando e `envrune`, o arquivo versionavel por projeto e `envrune.yml`, e a licenca da v1 e Apache-2.0.

## Escopo da v1

- Binario Go para Linux amd64; validado em Ubuntu 22.04/24.04, Debian 12 e WSL2 Ubuntu.
- Shells Bash e Zsh.
- Vault local com senha mestre, `init`, `set`, `list`, `link`, `usage`, `generate`, `import`, `run`, `export` e `ui`.
- Sem backend, conta, telemetria, cloud sync, Windows, macOS ou integracoes diretas a providers.
- `run` injeta valores em processos filhos. `export` e uma excecao explicita para carga manual em qualquer provider.

Ficam para versoes posteriores: adapters de sync (Vercel, AWS e outros), targets, historico de sync, compartilhamento e keyrings nativos.

## Modelo de seguranca

O Envrune protege vaults em repouso, backups e acessos de outros usuarios locais. Ele tambem reduz exposicao acidental por argumentos, historico de shell, logs, arquivos temporarios, configuracoes e UI.

Nao promete proteger contra root, kernel ou malware executando como o mesmo usuario enquanto um processo que recebeu secrets estiver ativo. Esse limite sera documentado de forma explicita.

Regras obrigatorias:

- Senha mestre solicitada interativamente; nunca persistida ou registrada.
- Sem daemon e sem cache de chave entre comandos.
- Sem valores em argumentos, stdout, stderr, logs, erros, YAML ou HTML.
- Sem arquivo `.env` temporario para `run`.
- Arquivos e diretorios locais com permissoes restritivas quando suportadas.
- UI somente em loopback e sem endpoint que revele valores.

## Criptografia e formato do vault

O vault fica em `$XDG_DATA_HOME/envrune/vault.ev1` ou, sem `XDG_DATA_HOME`, em `~/.local/share/envrune/vault.ev1`.

O arquivo binario `ev1` contem, em plaintext, somente magic, versao, parametros Argon2id, salt aleatorio e nonce. Esses bytes inteiros sao AAD da cifra. O restante e ciphertext autenticado XChaCha20-Poly1305.

O payload cifrado contem:

- registros de secret: referencia, valor e timestamps;
- registro de caminhos de projetos conhecidos;
- historico local de operacoes sem valores;
- versao do schema interno.

O leitor limita tamanho antes de alocar, valida comprimento e versao, e devolve a mesma falha generica para senha incorreta, corrupcao ou autenticacao invalida. Escritas usam lock exclusivo, arquivo temporario no mesmo diretorio, `fsync`, rename atomico e modo `0600`.

## Arquitetura

```text
CLI / UI
  -> application services
       -> domain
       -> vault | projeto | runner | generator | UI
```

O dominio nao conhece terminal, HTTP, YAML, Vercel ou sistema de arquivos. Casos de uso coordenam portas e adaptadores. O vault e a unica camada que converte ciphertext em valores; UI recebe apenas metadados.

```text
cmd/envrune/                 entrada do binario
internal/domain/             entidades e regras
internal/app/                casos de uso
internal/vault/              formato, lock e armazenamento
internal/crypto/             KDF, AEAD e limpeza de buffers
internal/project/            descoberta e YAML
internal/runner/             processo filho e ambiente
internal/generator/          CSPRNG
internal/ui/                 HTTP loopback e handlers
internal/platform/linux/     permissoes e prctl
web/                          templates e assets embutidos
```

## Configuracao de projeto

`envrune.yml` e seguro para versionamento porque nunca contem valores:

```yaml
version: 1
project: pulsewatch

environments:
  dev:
    OPENAI_API_KEY: openai.personal
    RESEND_API_KEY: resend.personal
    JWT_SECRET: pulsewatch.jwt.dev
  prod:
    OPENAI_API_KEY: openai.production
    RESEND_API_KEY: resend.production
    JWT_SECRET: pulsewatch.jwt.prod
```

O CLI procura esse arquivo do diretorio corrente ate a raiz. Referencias tem segmentos minusculos separados por ponto; variaveis obedecem a nomes POSIX. O parser aceita somente `VARIAVEL: referencia` nos environments.

`usage` percorre os arquivos dos projetos registrados, em vez de manter uma copia das referencias, para refletir sempre a configuracao atual.

## Comandos e comportamento

- `envrune init`: cria vault; no projeto atual, oferece criar `envrune.yml`.
- `envrune set <referencia>`: solicita valor sem eco e atualiza o vault.
- `envrune list`: lista referencias, nunca valores.
- `envrune link <VAR> <referencia> --env <ambiente>`: cria ou atualiza o vinculo no projeto atual.
- `envrune usage <referencia>`: mostra projetos e ambientes conhecidos que a usam.
- `envrune generate <VAR> --length <n>`: gera valor com CSPRNG, armazena-o e pode criar vinculo no projeto atual.
- `envrune import <arquivo.env>`: mostra os nomes detectados, pede confirmacao e nao remove o arquivo-fonte.
- `envrune run --env <ambiente> -- <comando>`: resolve referencias e executa diretamente o processo filho com o ambiente estendido.
- `envrune export --env <ambiente> [--output <caminho>]`: exportacao manual deliberada.
- `envrune ui`: inicia interface administrativa local.

`export` sem `--output` grava `./.env.<ambiente>` no diretorio atual. Ele lista somente nomes, solicita confirmacao, cria em modo `0600`, recusa sobrescrever sem `--force` e pede confirmacao adicional quando o destino estiver em um repositorio Git. O aviso informa que o arquivo possui plaintext e precisa ser apagado manualmente apos o uso.

## Runner Linux

`run` nao usa shell intermediario nem grava arquivos. Antes de `exec`, o processo filho recebe a protecao Linux de nao-dumpable quando possivel. Isso reduz acesso via `ptrace` e `/proc/<pid>/environ`; o comando permanece funcional caso o recurso nao exista, com aviso seguro.

O exit code e sinais do processo filho sao propagados. Segredos nao entram em argumentos do comando, mas fazem parte de seu ambiente enquanto ele estiver executando; esse risco residual e documentado.

## UI local

`ui` solicita senha mestre no terminal e mantem o vault aberto apenas durante a vida do processo. O servidor faz bind somente em `127.0.0.1`, escolhe porta livre ou aceita porta explicita, abre o navegador quando possivel e envia `Cache-Control: no-store`.

A UI usa templates Go e HTML simples. Ela mostra dashboard, projetos, referencias, ambientes e uso, mas nunca valores e nunca permite alteracao de valores. Valida Host e Origin, aplica CSRF em mutacoes e nao gera logs HTTP com dados sensiveis.

## Qualidade e verificacao

Cada fase inclui testes unitarios, integracao e testes de nao-vazamento. Sentinelas de secret verificam stdout, stderr, erros, logs, `envrune.yml`, conteudo externo do vault e respostas HTTP.

Tambem serao testados KDF e AEAD, cabecalho adulterado, vault corrompido, senha incorreta, lock concorrente, permissoes, importacao, ambiente do processo filho, Ctrl+C e propagacao de status. Validacao manual cobre Bash e Zsh nos sistemas Linux-alvo.

## Fases

1. Core seguro: dominio, crypto, vault, `init`, `set`, `list` e testes.
2. Projetos: YAML, descoberta, `link`, `usage` e testes.
3. Runtime: `generate`, `import`, `run`, `export` e testes de processo/vazamento.
4. UI: servidor loopback, templates, protecoes HTTP e testes.

Cada fase precisa passar sua suite antes da seguinte.
