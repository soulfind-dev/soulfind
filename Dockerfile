# SPDX-FileCopyrightText: 2025 Soulfind Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

# Build binaries
FROM alpine:edge as builder
RUN adduser -D soulfind
RUN apk update && apk add dub gcc ldc lld20 musl-dev sqlite-static
WORKDIR /build
COPY . .
RUN dub build -v --build=release-debug --config=static

# Create image
FROM scratch
COPY --from=builder /build/bin /bin
COPY --from=builder /etc/passwd /etc/passwd
USER soulfind
WORKDIR /data
CMD ["soulfind"]
