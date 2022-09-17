FROM golang:alpine as build 
RUN apk update && apk add --no-cache git 
RUN apk add build-base
ENV GOPATH ""
RUN go env -w GOPROXY=direct
ADD go.mod go.sum ./
RUN go mod download 
ADD . .
RUN go build -o /main 

FROM alpine 
COPY . .
COPY --from=build /main /main
ENTRYPOINT ["/main"]
