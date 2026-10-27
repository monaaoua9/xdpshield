FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# generated bpf object is committed, so no clang needed here
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /xdpshield ./cmd/xdpshield

FROM gcr.io/distroless/static-debian12
COPY --from=build /xdpshield /xdpshield
# needs --net=host --cap-add=NET_ADMIN --cap-add=BPF --cap-add=PERFMON (or --privileged on old kernels)
ENTRYPOINT ["/xdpshield"]
CMD ["-config", "/etc/xdpshield/config.yaml"]
