# Hashmaker

Gerador de hashes de senha em múltiplos algoritmos, escrito em Rust com SPA embutida.

## Algoritmos suportados

| Algoritmo | Tipo | Descrição |
|-----------|------|-----------|
| MD5 | digest | Legacy — não usar para senhas |
| SHA-1 | digest | Deprecated para segurança |
| SHA-256 / SHA-512 | digest | SHA-2 |
| SHA3-256 / SHA3-512 | digest | SHA-3 |
| BLAKE2b / BLAKE2s | digest | Hash rápido |
| bcrypt | senha | Hash adaptativo com salt |
| Argon2id | senha | Recomendado para senhas |
| PBKDF2-SHA256 | senha | KDF com iterações configuráveis |
| scrypt | senha | KDF memory-hard |

## Executar

```bash
cargo run
```

Por padrão escuta na porta **8080** (a 3000 costuma estar ocupada por outros apps). Use `PORT=3000 cargo run` se preferir.

Abra [http://localhost:3000](http://localhost:3000).

## Build de produção

```bash
cargo build --release
./target/release/hashmaker
```

O binário inclui a SPA — não é necessário servir arquivos estáticos separados.

## API

### `GET /api/algorithms`

Lista algoritmos disponíveis.

### `POST /api/hash`

```json
{
  "password": "minha-senha",
  "algorithms": ["sha256", "argon2id"],
  "options": {
    "bcrypt_cost": 12,
    "pbkdf2_iterations": 100000
  }
}
```

Resposta:

```json
{
  "results": [
    { "algorithm": "sha256", "label": "SHA-256", "hash": "...", "category": "digest" }
  ],
  "errors": []
}
```

## Licença

MIT
