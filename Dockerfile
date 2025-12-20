FROM golang:1.25 as build

# create a working directory inside the image
WORKDIR /app

# copy Go modules and dependencies to image
COPY go.mod ./
COPY go.sum ./

# download Go modules and dependencies
RUN go mod download

# copy directory files i.e all files ending with .go
COPY ./cmd/auth/auth.go ./
COPY ./cmd/manager/manager.go ./
COPY ./internal ./internal
COPY ./pkg ./pkg

# compile application
RUN go build -o /app/auth ./auth.go
RUN go build -o /app/manager ./manager.go

FROM ubuntu:latest

WORKDIR /app

COPY --from=build /app/auth /app/auth
COPY --from=build /app/manager /app/manager
COPY ./templates /app/templates

RUN chmod +x /app/auth


# command to be used to execute when the image is used to start a container
CMD [ "/app/auth" ]