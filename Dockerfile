FROM golang:1.22 as buildgo

WORKDIR /go/src/github.com/shieldoo/shieldoo-mesh-admin/
COPY go.mod .
COPY go.sum .
RUN go get ./...
RUN go mod download 

COPY main/ ./main/
COPY shieldoo.go .
COPY tools.go .
COPY cliapi/ ./cliapi/
COPY app/ ./app/
COPY authserver/ ./authserver/
COPY graph/ ./graph/
COPY logstore/ ./logstore/
COPY job/ ./job/
COPY aadimport/ ./aadimport/
COPY model/ ./model/
COPY myjwt/ ./myjwt/
COPY ncert/ ./ncert/
COPY utils/ ./utils/
RUN go test ./...
RUN go build -o out/shd-admin ./main/

FROM alpine:latest as final
RUN apk --no-cache add ca-certificates
RUN apk add --no-cache libc6-compat gcompat
# run as user 1000
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app/
COPY --from=buildgo /go/src/github.com/shieldoo/shieldoo-mesh-admin/out/ .
RUN chown -R appuser:appgroup /app/* 
USER appuser
CMD ["./shd-admin"]  
