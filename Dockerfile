# 多阶段构建：最终镜像只有一个静态二进制
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go env -w GOPROXY=https://goproxy.cn,direct && go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/keybaton ./cmd/keybaton

FROM alpine:3.20
RUN adduser -D -u 10001 kb
COPY --from=build /out/keybaton /usr/local/bin/keybaton
# 注意：容器内监听 0.0.0.0，启动时必须提供 KEYBATON_TOKEN（-e KEYBATON_TOKEN=...），
# 否则服务会按安全策略拒绝启动。
USER kb
WORKDIR /home/kb
VOLUME ["/home/kb/.keybaton"]
EXPOSE 8765
ENTRYPOINT ["keybaton"]
CMD ["serve", "--addr", "0.0.0.0:8765"]
