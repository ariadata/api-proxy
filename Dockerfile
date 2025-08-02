FROM golang:1.24.3-alpine AS builder

# Install required system packages and update certificates
RUN apk update && \
    apk upgrade && \
    apk add --no-cache ca-certificates && \
    update-ca-certificates

# Add Maintainer Info to the Image
LABEL maintainer="Mehrdad Amini <pcmehrdad@gmail.com>"
LABEL description="API Proxy Service"

# Set the Current Working Directory inside the container
WORKDIR /build/api-proxy

# Copy go mod files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code
COPY main.go .

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o api-proxy .

# Start a new stage for final image
#FROM scratch
FROM gcr.io/distroless/static-debian11

WORKDIR /app

# Copy binary and configuration
COPY --from=builder /build/api-proxy/api-proxy .
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY config.json.example ./config.json

# Expose port
EXPOSE 3000

# Command to run
CMD ["./api-proxy"]