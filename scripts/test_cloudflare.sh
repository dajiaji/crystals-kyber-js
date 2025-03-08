#!/bin/sh
(cd ./npm/test/crystals-kyber-js/runtimes/cloudflare && npm ci && npm run test)
(cd ./npm/test/mlkem/runtimes/cloudflare && npm ci && npm run test)