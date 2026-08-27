# EP Witness cosigner — minimal, zero runtime dependencies.
#
# The service imports the signing digest and domain tag from the in-repo
# @emilia-protocol/verify package, so this image copies both the witness/ dir
# and packages/verify/. Build from the REPO ROOT so both paths are in context:
#
#   docker build -f witness/Dockerfile -t ep-witness .
#
FROM node:22.23.1-alpine3.24@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2

RUN apk add --no-cache --upgrade libcrypto3=3.5.8-r0 libssl3=3.5.8-r0 \
    && rm -rf /usr/local/lib/node_modules/npm \
                 /usr/local/lib/node_modules/corepack \
                 /opt/yarn-v1.22.22 \
    && rm -f /usr/local/bin/npm \
               /usr/local/bin/npx \
               /usr/local/bin/corepack \
               /usr/local/bin/yarn \
               /usr/local/bin/yarnpkg

WORKDIR /app

# The verify package (source of the canonicalization + witness digest) and the
# witness service itself. No npm install: both are dependency-free ESM.
COPY packages/verify ./packages/verify
COPY witness ./witness

WORKDIR /app/witness

# Keys are provided at runtime, never baked into the image:
#   - mount a key file and point WITNESS_PRIVATE_KEY_FILE at it, OR
#   - pass the PEM literal via WITNESS_PRIVATE_KEY.
ENV PORT=8787
EXPOSE 8787

# Run as the unprivileged 'node' user shipped in the base image.
USER node

# Fail closed: with no key configured the server logs the reason and exits 1.
CMD ["node", "server.mjs"]
