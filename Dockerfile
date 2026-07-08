# Pin the Rust toolchain version used in the build stage.
ARG RUST_VERSION=1.96

# Name of the compiled binary produced by Cargo (must match Cargo.toml package name).
ARG APP_NAME=turnip_server

################################################################################
# Build stage (DOI Rust image)
# This stage compiles the application.
################################################################################

FROM docker.io/library/rust:${RUST_VERSION}-alpine AS build

# Re-declare args inside the stage if you want to use them here.
ARG APP_NAME

# All build steps happen inside /app.
WORKDIR /app

# Install build dependencies needed to compile Rust crates on Alpine
RUN apk add --no-cache clang lld musl-dev git

# Build the application
RUN --mount=type=bind,source=turnip_api,target=turnip_api \
    --mount=type=bind,source=turnip_api_looper,target=turnip_api_looper \
    --mount=type=bind,source=turnip_api_search,target=turnip_api_search \
    --mount=type=bind,source=turnip_api_weather,target=turnip_api_weather \
    --mount=type=bind,source=turnip_server,target=turnip_server \
    --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock \
    --mount=type=cache,target=/app/target/ \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    cargo build --locked --release && \
    cp ./target/release/$APP_NAME /bin/server

################################################################################
# Runtime stage (DOI Alpine image)
# This stage runs the already-compiled binary with minimal dependencies.
################################################################################

FROM docker.io/library/alpine:3.18 AS final

# Create a non-privileged user (recommended best practice)
ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    appuser

# Drop privileges for runtime.
USER appuser

# Copy only the compiled binary from the build stage.
COPY --from=build /bin/server /bin/

# Set and document the active port
ENV TURNIP_SERVER_IP=0.0.0.0
ENV TURNIP_SERVER_PORT=3000
ENV RUST_LOG=info
EXPOSE 3000

# Start the application.
CMD ["/bin/server"]
