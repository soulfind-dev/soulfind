# SPDX-FileCopyrightText: 2025 Soulfind Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

# Build binaries
FROM alpine:edge AS builder
WORKDIR /build
RUN apk update && apk add dub gcc ldc musl-dev sqlite-static
RUN echo "soulfind:x:1000:1000:soulfind::/sbin/nologin" > passwd
COPY . .
RUN dub build -v --build=release-debug --config=static

# Create image
FROM scratch
COPY --from=builder /build/bin /bin
COPY --from=builder /build/passwd /etc/passwd
USER soulfind
WORKDIR /data
CMD ["soulfind"]
