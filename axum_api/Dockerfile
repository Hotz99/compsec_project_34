# Use Rust slim image as base
FROM rust:slim-bullseye AS builder

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Build the application in release mode
RUN cargo build --release && ls -lah /app/target/release/

# Use a smaller base image for the final runtime
FROM debian:bullseye-slim

# Install OpenSSL runtime (needed for TLS support)
RUN apt-get update && apt-get install -y \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/release/axum_api /app/axum_api

# Ensure the binary is executable
RUN chmod +x /app/axum_api

# Expose necessary ports
EXPOSE 3000

# Run the Rust application
CMD ["/app/axum_api"]
