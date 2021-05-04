FROM golang:1.16.3-alpine3.12 as build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY check ./check
COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -i -ldflags "-w -s -extldflags '-static'" -o /src/sslhound-matrix ./cmd/main.go

FROM alpine:3.12 as server
RUN apk add --no-cache --update ca-certificates tzdata
RUN mkdir -p /app
WORKDIR /app
COPY --from=build /src/sslhound-matrix /go/bin/
ENTRYPOINT ["/go/bin/sslhound-matrix"]
