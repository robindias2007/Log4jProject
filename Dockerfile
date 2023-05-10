# Base image for Ubuntu
FROM ubuntu:latest

# Update packages and install curl
RUN apt-get update && apt-get install -y curl

# Base image for Alpine
FROM alpine:latest

# Update packages and install curl
RUN apk update && apk add curl

# Start containers on Ubuntu
CMD ["bash", "-c", "curl https://www.google.com; sleep 3600"]
CMD ["bash", "-c", "curl https://www.yahoo.com; sleep 3600"]
CMD ["bash", "-c", "curl https://www.github.com; sleep 3600"]

# Start containers on Alpine
CMD ["ash", "-c", "curl https://www.google.com; sleep 3600"]
CMD ["ash", "-c", "curl https://www.yahoo.com; sleep 3600"]
CMD ["ash", "-c", "curl https://www.github.com; sleep 3600"]

