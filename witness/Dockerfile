# EP Witness cosigner — minimal, zero runtime dependencies.
#
# The service imports the signing digest and domain tag from the in-repo
# @emilia-protocol/verify package, so this image copies both the witness/ dir
# and packages/verify/. Build from the REPO ROOT so both paths are in context:
#
#   docker build -f witness/Dockerfile -t ep-witness .
#
FROM node:22-alpine

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
