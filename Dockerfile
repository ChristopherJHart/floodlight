FROM alpine:latest

ARG GITLAB_TOKEN
ENV GITLAB_TOKEN=$GITLAB_TOKEN

RUN export http_proxy=http://proxy.esl.cisco.com:80/
RUN export https_proxy=https://proxy.esl.cisco.com:80/
RUN apk --update --no-cache add tshark python3 git gcc musl-dev python3-dev libxml2-dev libxslt1-dev
RUN git clone https://gitlab-ci-token:$GITLAB_TOKEN@gitlab-sjc.cisco.com/docker-projects/Floodlight.git /floodlight
RUN pip3 install -r /floodlight/requirements.txt
RUN python3 -m ensurepip