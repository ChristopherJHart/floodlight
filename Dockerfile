FROM alpine:latest

RUN apk --update --no-cache add python3-dev git tcpdump gcc g++ libxml2 libxslt-dev tshark
RUN pip3 install --upgrade pip
RUN git clone https://github.com/ChristopherJHart/floodlight.git /floodlight
RUN pip3 install -r /floodlight/requirements.txt
CMD [ "python3", "-u", "/floodlight/floodlight.py" ]