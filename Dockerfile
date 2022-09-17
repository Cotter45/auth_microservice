FROM node:16-alpine as build-node 
WORKDIR /frontend
COPY frontend/ .
ENV REACT_APP_BASE_URL=https://go-tasks-api.herokuapp.com
RUN npm install
RUN npm run build

FROM golang:alpine as build 
RUN apk update && apk add --no-cache git 
ENV GOPATH ""
RUN go env -w GOPROXY=direct
ADD go.mod go.sum ./
RUN go mod download 
ADD . .
RUN go build -o /main 

FROM alpine 
COPY --from=build-node /frontend/build ./frontend/build
COPY --from=build /main /main
ENTRYPOINT ["/main"]
