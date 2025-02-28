# monitor_login
Monitor Ubuntu SSH login and send alarm notifications to WeChat.

This project monitors SSH login events on an Ubuntu system and sends alarm notifications via WeChat (using a webhook). It leverages Docker to run a Python script that reads the SSH logs and sends alerts for both successful and failed login attempts.

## Prerequisites

- Docker
- Docker Compose
- Python 3 (inside the Docker container)

## Steps to Set Up

### 1. Build the Docker Image

To build the Docker image, use the following command:

```bash
docker build -t monitor_login .
```
This command builds the Docker image with the tag monitor_login using the Dockerfile in the current directory.

### 2. Set Up Docker Compose

Create a docker-compose.yml file with the following content:

```bash
version: '3.8'
services:
  login-monitor:
    image: monitor_login
    command: python -u /app/monitor.py /app/auth.log webhook_weixin_token
    volumes:
      - /var/log/auth.log:/app/auth.log:ro
    restart: always
```

This file defines a service login-monitor that runs the monitor.py script to monitor the SSH log file (/var/log/auth.log) for login attempts. The WeChat webhook token (webhook_weixin_token) is passed as an argument to send the notifications.

### 3. Run the Application with Docker Compose

Once the docker-compose.yml file is set up, run the following command to start the container:

```bash
docker-compose up -d
```

This will start the login-monitor service in detached mode. The -d flag ensures the container runs in the background.

