#!/bin/sh
set -e
(cd ./npm/test/mlkem/runtimes/cloudflare && npm ci && npm run test)
(cd ./npm/test/webpqc-mldsa/runtimes/cloudflare && npm ci && npm run typecheck && npm run test)
