FROM alpine:latest

ARG BUILD_DATE
ARG VCS_REF

LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="Floodlight" \
      org.label-schema.description="Python application to identify and display unexpected control plane traffic on Cisco Nexus data center switches" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/ChristopherJHart/floodlight" \
      org.label-schema.schema-version="1.0"

RUN apk --update --no-cache add python3-dev git gcc g++ libxml2 libxslt-dev tshark
RUN pip3 install --upgrade pip
RUN mkdir /floodlight
ADD . /floodlight
RUN pip3 install -r /floodlight/requirements.txt
CMD [ "python3", "-u", "/floodlight/floodlight.py" ]