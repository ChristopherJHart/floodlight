FROM alpine:latest

RUN export PS4='\t '
ARG GITLAB_TOKEN
ENV GITLAB_TOKEN=$GITLAB_TOKEN

RUN export http_proxy=http://proxy.esl.cisco.com:80/
RUN export https_proxy=https://proxy.esl.cisco.com:80/
RUN apk --update --no-cache add python3-dev git tcpdump gcc g++ libxml2 libxslt-dev
RUN pip3 install --upgrade pip
RUN git clone https://gitlab-ci-token:$GITLAB_TOKEN@gitlab-sjc.cisco.com/docker-projects/Floodlight.git /floodlight
RUN pip3 install -r /floodlight/requirements.txt
RUN python3 -m ensurepip
CMD [ "python3", "-u", "/floodlight/floodlight.py" ]