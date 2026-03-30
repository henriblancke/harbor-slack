FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /harbor-slack .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates && \
    adduser -D appuser
USER appuser
COPY --from=build /harbor-slack /harbor-slack
EXPOSE 8080
ENTRYPOINT ["/harbor-slack"]
