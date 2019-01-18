FROM alpine:latest

RUN apk --update --no-cache add python3-dev git gcc g++ libxml2 libxslt-dev tshark
RUN pip3 install --upgrade pip
RUN mkdir /floodlight
ADD . /floodlight
RUN pip3 install -r /floodlight/requirements.txt
CMD [ "python3", "-u", "/floodlight/floodlight.py" ]