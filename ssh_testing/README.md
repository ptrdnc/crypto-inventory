# Dockerized SSH Server with Public Key Authentication

This project provides a clean and robust way to run an SSH server inside a Docker container, configured to only allow connections authenticated with a specific public key.

This setup is ideal for creating a consistent and isolated development or testing environment that mimics a remote server.

### Prerequisites

    Docker and Docker Compose must be installed on your local machine.

    An SSH client (like OpenSSH) must be available on your local machine.

### Project Structure

To keep things organized, create the following directory and file structure on your local machine:
```
ssh-docker-environment/
├── docker-compose.yml
└── remote/
    └── Dockerfile
```

    
## Step 1: Generate Your SSH Key Pair

If you don't already have an SSH key pair, generate one on your local machine (not inside Docker).

    Open your terminal.

    Run the following command. It's recommended to use the ed25519 algorithm, which is modern and secure.

    ssh-keygen -t ed25519 -C "your_email@example.com"

    When prompted, you can press Enter to save the key to the default location (~/.ssh/id_ed25519) and optionally set a passphrase for added security.

This will create two files:

    ~/.ssh/id_ed25519 (Your private key - keep this safe!)

    ~/.ssh/id_ed25519.pub (Your public key - this is what you'll share)

## Step 2: Create the Docker Files

Create the docker-compose.yml and remote/Dockerfile files as shown in the code blocks provided in the other documents. Place them in the structure outlined above.

## Step 3: Build and Run the SSH Server

Now you will build the Docker image for the SSH server. During the build process, you will securely pass your public key into the container.

    Navigate to the root of your project directory (ssh-docker-environment/) in your terminal.

    Run the following command. It reads your public key file and passes it as a build argument to Docker Compose.

    PUBLIC_KEY="$(cat ~/.ssh/id_ed25519.pub)" docker-compose up --build -d

        PUBLIC_KEY="$(cat ...)": This captures the content of your public key into an environment variable.

        docker-compose up: This command reads your docker-compose.yml file to build and start the services.

        --build: This forces Docker to build the image, ensuring your public key is added.

        -d: This runs the container in detached mode (in the background).

Your secure SSH server is now running!

## Step 4: Connect to Your Server

You can now SSH into the container from your local machine.

    Use the following command. Note that we are connecting to localhost on port 2222, which is mapped to the container's port 22.

    ssh -i ~/.ssh/id_ed25519.pub -p 2222 sshuser@localhost

    The first time you connect, you may be asked to verify the host's fingerprint. Type yes and press Enter.
    If you set a passphrase for your SSH key, you will be prompted to enter it.

    If "remote host identification has changed" warning shows up run this command
    
    ssh-keygen -f '/home/user/.ssh/known_hosts' -R '[localhost]:2222'
    
    And then use the previous command

    ssh -i ~/.ssh/id_ed25519.pub -p 2222 sshuser@localhost



You are now successfully connected to the shell inside your secure Docker container!
Managing the Server

    To stop the server:

    docker-compose down

    To start the server again:

    docker-compose up -d

    To view logs:

    docker-compose logs -f

