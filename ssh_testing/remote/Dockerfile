# remote/Dockerfile
# This Dockerfile sets up a secure SSH server based on Ubuntu.

# Use the latest long-term support version of Ubuntu as the base image
FROM ubuntu:22.04

# --- Build-time Arguments ---
# Declare a build-time argument to accept the public key.
# This is a secure way to pass secrets at build time without leaving them in the final image layers.
ARG PUBLIC_KEY

# --- Environment Variables ---
# Set DEBIAN_FRONTEND to noninteractive to prevent prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# --- Package Installation and Setup ---
# Update package lists and install the OpenSSH server
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Create a dedicated, non-root user for SSH access for security best practices.
# -m creates the home directory (/home/sshuser)
# -s specifies the user's default shell
RUN useradd -m -s /bin/bash sshuser

# Create the .ssh directory in the user's home directory
RUN mkdir -p /home/sshuser/.ssh

# --- Public Key and Permissions Configuration ---
# Use the PUBLIC_KEY build argument to create the authorized_keys file.
# This check ensures that the build fails if the PUBLIC_KEY is not provided.
RUN if [ -z "$PUBLIC_KEY" ]; then echo "Error: PUBLIC_KEY build-arg is not set" && exit 1; else echo "$PUBLIC_KEY" > /home/sshuser/.ssh/authorized_keys; fi

# Set the correct, strict permissions for the .ssh directory and authorized_keys file.
# SSH will refuse to use keys if permissions are too open.
# 700 for .ssh: Only the owner can read, write, and execute.
# 600 for authorized_keys: Only the owner can read and write.
RUN chown -R sshuser:sshuser /home/sshuser/.ssh && \
    chmod 700 /home/sshuser/.ssh && \
    chmod 600 /home/sshuser/.ssh/authorized_keys

# --- SSH Server Configuration ---
# Create the directory needed for the SSH daemon to run
RUN mkdir /var/run/sshd

# Expose port 22 to allow network connections to the container
EXPOSE 22

# --- Entrypoint ---
# The main command to run when the container starts.
# `/usr/sbin/sshd -D` starts the SSH daemon in the foreground, which is required for Docker containers.
CMD ["/usr/sbin/sshd", "-D"]
