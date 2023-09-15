FROM golang:1.19.5-alpine AS BUILDER

WORKDIR /app

COPY . /app/

RUN go get -d -v ./...

RUN go install -v ./...

RUN export GO111MODULE=on

RUN go build

RUN ls -ltr

FROM alpine

RUN apk add py3-pip gcc libc-dev linux-headers alpine-sdk python3-dev g++ libffi-dev openssl-dev

WORKDIR /

COPY --from=BUILDER /app/vls-api /

RUN ls -ltr

EXPOSE 3000

ENTRYPOINT [ "./vls-api" ]
