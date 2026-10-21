# Gourmet Security Emergency (GSE)

Sistema offline de resposta a incidentes e rotacao emergencial de segredos.

## Principios

- Offline-first
- Nenhum segredo real armazenado no repositorio
- Scripts enviados temporariamente ao servidor
- Backup antes de qualquer alteracao critica
- Rollback obrigatorio
- Logs sanitizados
- Producao exige confirmacao explicita
- Chaves ligadas a dados persistidos nunca sao rotacionadas automaticamente

## Estado atual

GSE-01 Emergency Core em construcao.

## Comandos planejados

gse audit
gse status
gse preflight
gse verify
gse incident
gse rotate-safe
gse rollback
