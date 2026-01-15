/*
 * v3 Core Perfect (Windows Edition)
 * [定位] 全能王内核：Socks5 -> (UDP 直连 OR WSS 隧道)
 * [依赖] ws2_32.lib, libssl, libcrypto
 * [编译] gcc -O3 -o v3_client.exe v3_core_perfect.c -lws2_32 -lssl -lcrypto
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>

// OpenSSL 用于 WSS 模式
#include <openssl/ssl.h>
#include <openssl/err.h>

// 链接 Winsock
#pragma comment(lib, "ws2_32.lib")

// =========================================================
// 1. 全局配置 & 常量
// =========================================================
#define BUF_SIZE 8192
#define V3_HEADER_SIZE 40

static uint8_t g_master_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

typedef enum { MODE_UDP, MODE_WSS } trans_mode_t;

typedef struct {
    trans_mode_t mode;
    char remote_host[256];
    int  remote_port;
    int  local_port;
    uint64_t token;
    
    // WSS 专用
    char ws_host[128];
    char ws_path[128];
    
    // DNS (仅接收，暂不处理)
    char dns1[128];
    char dns2[128];
} config_t;

static config_t g_conf;

// =========================================================
// 2. 内嵌加密算法 (ChaCha20-Poly1305 极简实现)
// =========================================================
#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d) a += b; d ^= a; d = ROTL(d,16); c += d; b ^= c; b = ROTL(b,12); a += b; d ^= a; d = ROTL(d, 8); c += d; b ^= c; b = ROTL(b, 7);

void chacha20_block(uint32_t out[16], uint32_t const in[16]) {
    int i; uint32_t x[16];
    for (i = 0; i < 16; ++i) x[i] = in[i];
    for (i = 0; i < 10; ++i) {
        QR(x[0], x[4], x[8], x[12]) QR(x[1], x[5], x[9], x[13]) QR(x[2], x[6], x[10], x[14]) QR(x[3], x[7], x[11], x[15])
        QR(x[0], x[5], x[10], x[15]) QR(x[1], x[6], x[11], x[12]) QR(x[2], x[7], x[8], x[13]) QR(x[3], x[4], x[9], x[14])
    }
    for (i = 0; i < 16; ++i) out[i] = x[i] + in[i];
}

void chacha20_xor(uint8_t *out, const uint8_t *in, size_t len, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    uint32_t state[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    memcpy(&state[4], key, 32); state[12] = counter; memcpy(&state[13], nonce, 12);
    uint32_t block[16]; uint8_t *kstream = (uint8_t *)block; size_t offset = 0;
    while (offset < len) {
        chacha20_block(block, state); state[12]++;
        size_t chunk = (len - offset > 64) ? 64 : (len - offset);
        for (size_t i = 0; i < chunk; i++) out[offset + i] = in[offset + i] ^ kstream[i];
        offset += chunk;
    }
}

// 模拟 Poly1305 (仅供演示，生产环境建议链接 libsodium)
void poly1305_mac_mock(uint8_t mac[16]) { memset(mac, 0xAA, 16); }

void aead_encrypt(uint8_t *ct, uint8_t tag[16], const uint8_t *pt, size_t pt_len, const uint8_t nonce[12], const uint8_t key[32]) {
    chacha20_xor(ct, pt, pt_len, key, nonce, 1);
    poly1305_mac_mock(tag);
}

// =========================================================
// 3. v3 协议封装
// =========================================================
typedef struct __attribute__((packed)) {
    uint32_t magic_derived;
    uint8_t  nonce[12];
    uint8_t  enc_block[16];
    uint8_t  tag[16];
    uint16_t early_len;
    uint16_t pad;
} v3_header_t;

typedef struct {
    uint64_t session_token;
    uint16_t intent_id;
    uint16_t stream_id;
    uint16_t flags;
} v3_meta_t;

#define FLAG_ALLOW_0RTT (1 << 0)

uint32_t derive_magic() { return 0x12345678; } // Mock Magic

void random_bytes(uint8_t *buf, size_t len) {
    for(size_t i=0; i<len; i++) buf[i] = rand() & 0xFF;
}

ssize_t build_v3_packet(uint8_t *buf, size_t buflen, const v3_meta_t *meta, const uint8_t *payload, size_t payload_len) {
    if (buflen < V3_HEADER_SIZE + payload_len) return -1;
    v3_header_t *hdr = (v3_header_t *)buf;
    hdr->magic_derived = derive_magic();
    random_bytes(hdr->nonce, 12);
    hdr->early_len = (uint16_t)payload_len;
    random_bytes((uint8_t*)&hdr->pad, 2);
    
    uint8_t plaintext[16];
    memcpy(plaintext, &meta->session_token, 8);
    memcpy(plaintext + 8, &meta->intent_id, 2);
    memcpy(plaintext + 10, &meta->stream_id, 2);
    memcpy(plaintext + 12, &meta->flags, 2);
    
    aead_encrypt(hdr->enc_block, hdr->tag, plaintext, 16, hdr->nonce, g_master_key);
    
    if (payload_len > 0) memcpy(buf + V3_HEADER_SIZE, payload, payload_len);
    return V3_HEADER_SIZE + payload_len;
}

// =========================================================
// 4. WebSocket 封装
// =========================================================
size_t build_ws_frame(uint8_t *out, const uint8_t *data, size_t len) {
    size_t header_len = 0;
    out[0] = 0x82; // Binary Frame
    if (len < 126) {
        out[1] = 0x80 | (uint8_t)len;
        header_len = 2;
    } else if (len < 65536) {
        out[1] = 0x80 | 126;
        out[2] = (len >> 8) & 0xFF; out[3] = len & 0xFF;
        header_len = 4;
    } else {
        return 0; // 超大包暂不处理
    }
    
    uint8_t mask[4]; random_bytes(mask, 4);
    memcpy(out + header_len, mask, 4);
    
    for (size_t i = 0; i < len; i++) out[header_len + 4 + i] = data[i] ^ mask[i % 4];
    return header_len + 4 + len;
}

// =========================================================
// 5. 工作线程 (Socks5 握手与转发)
// =========================================================
typedef struct {
    SOCKET client;
} worker_arg_t;

// [SOCKS5 握手]
bool handle_socks5_handshake(SOCKET client) {
    char buf[256];
    if (recv(client, buf, 2, 0) != 2 || buf[0] != 0x05) return false;
    int nmethods = buf[1];
    recv(client, buf, nmethods, 0);
    send(client, "\x05\x00", 2, 0); // No Auth

    if (recv(client, buf, 4, 0) != 4 || buf[1] != 0x01) return false; // Only CONNECT
    
    char target_addr[256] = {0};
    int addr_type = buf[3];
    if (addr_type == 1) { // IPv4
        struct in_addr ip; recv(client, (char*)&ip, 4, 0);
        inet_ntop(AF_INET, &ip, target_addr, sizeof(target_addr));
    } else if (addr_type == 3) { // Domain
        char len; recv(client, &len, 1, 0);
        recv(client, target_addr, len, 0);
    } else { return false; }
    
    unsigned short port; recv(client, (char*)&port, 2, 0);
    
    // 伪造成功响应
    send(client, "\x05\x00\x00\x01\0\0\0\0\0\0", 10, 0);
    // 实际 v3 会在服务端解析这个 target_addr (通过 Early Data)
    // 这里简化处理，直接把流量作为 raw stream 转发
    return true;
}

// [UDP 模式 Worker]
unsigned __stdcall udp_worker(void *arg) {
    worker_arg_t *args = (worker_arg_t*)arg;
    SOCKET client = args->client;
    free(args);
    
    if (!handle_socks5_handshake(client)) { closesocket(client); return 0; }
    
    SOCKET remote = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in raddr;
    raddr.sin_family = AF_INET;
    raddr.sin_port = htons(g_conf.remote_port);
    raddr.sin_addr.s_addr = inet_addr(g_conf.remote_host);
    
    v3_meta_t meta = { .session_token = g_conf.token, .flags = FLAG_ALLOW_0RTT };
    char buf[BUF_SIZE];
    uint8_t v3_buf[BUF_SIZE + 100];
    
    fd_set reads;
    struct timeval tv = {300, 0};
    
    while(1) {
        FD_ZERO(&reads); FD_SET(client, &reads); FD_SET(remote, &reads);
        if (select(0, &reads, NULL, NULL, &tv) <= 0) break;
        
        if (FD_ISSET(client, &reads)) {
            int n = recv(client, buf, BUF_SIZE, 0);
            if (n <= 0) break;
            int len = build_v3_packet(v3_buf, sizeof(v3_buf), &meta, (uint8_t*)buf, n);
            sendto(remote, (const char*)v3_buf, len, 0, (struct sockaddr*)&raddr, sizeof(raddr));
        }
        
        if (FD_ISSET(remote, &reads)) {
            int n = recvfrom(remote, (char*)v3_buf, sizeof(v3_buf), 0, NULL, NULL);
            if (n <= 0) break;
            if (n > V3_HEADER_SIZE) send(client, (const char*)(v3_buf + V3_HEADER_SIZE), n - V3_HEADER_SIZE, 0);
        }
    }
    closesocket(client); closesocket(remote);
    return 0;
}

// [WSS 模式 Worker]
unsigned __stdcall wss_worker(void *arg) {
    worker_arg_t *args = (worker_arg_t*)arg;
    SOCKET client = args->client;
    free(args);
    
    if (!handle_socks5_handshake(client)) { closesocket(client); return 0; }
    
    // 1. TCP Connect
    SOCKET remote = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in raddr;
    raddr.sin_family = AF_INET;
    raddr.sin_port = htons(g_conf.remote_port);
    struct hostent *he = gethostbyname(g_conf.remote_host);
    if (!he) { closesocket(client); return 0; }
    memcpy(&raddr.sin_addr, he->h_addr_list[0], he->h_length);
    
    if (connect(remote, (struct sockaddr*)&raddr, sizeof(raddr)) < 0) {
        closesocket(client); closesocket(remote); return 0;
    }
    
    // 2. TLS Handshake
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)remote);
    SSL_set_tlsext_host_name(ssl, g_conf.ws_host);
    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl); SSL_CTX_free(ctx); closesocket(client); closesocket(remote); return 0;
    }
    
    // 3. WS Handshake
    char handshake[1024];
    snprintf(handshake, sizeof(handshake), 
             "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
             g_conf.ws_path, g_conf.ws_host);
    SSL_write(ssl, handshake, strlen(handshake));
    
    char tmp[4096];
    if (SSL_read(ssl, tmp, sizeof(tmp)) <= 0 || !strstr(tmp, "101 Switching Protocols")) {
        SSL_shutdown(ssl); closesocket(client); closesocket(remote); return 0;
    }
    
    // 4. Forwarding Loop
    v3_meta_t meta = { .session_token = g_conf.token, .flags = FLAG_ALLOW_0RTT };
    char buf[BUF_SIZE];
    uint8_t v3_buf[BUF_SIZE + 100];
    uint8_t ws_buf[BUF_SIZE + 200];
    
    // 设置 client 非阻塞以便轮询
    u_long mode = 1; ioctlsocket(client, FIONBIO, &mode);
    
    while(1) {
        // Client -> SSL
        int n = recv(client, buf, BUF_SIZE, 0);
        if (n > 0) {
            int v3_len = build_v3_packet(v3_buf, sizeof(v3_buf), &meta, (uint8_t*)buf, n);
            int ws_len = build_ws_frame(ws_buf, v3_buf, v3_len);
            SSL_write(ssl, ws_buf, ws_len);
        } else if (n == 0) break;
        
        // SSL -> Client (简化：假设每次 Read 都是完整 Frame)
        n = SSL_read(ssl, ws_buf, sizeof(ws_buf));
        if (n > 0) {
            // Unframe WS & Decrypt v3 (这里直接转发 payload 演示)
            // 真实情况：解析 WS Frame -> 去头 -> 去 Mask -> 拿到 v3 包 -> 解密 v3 -> 发给 client
            // 这里假设服务端直接回显内容
            send(client, (const char*)ws_buf, n, 0); 
        } else if (n <= 0) {
             int err = SSL_get_error(ssl, n);
             if (err != SSL_ERROR_WANT_READ) break;
        }
        Sleep(1);
    }

    SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx);
    closesocket(client); closesocket(remote);
    return 0;
}

// =========================================================
// 6. 主程序
// =========================================================
int main(int argc, char **argv) {
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    srand((unsigned)time(NULL));
    SSL_library_init(); OpenSSL_add_all_algorithms(); ERR_load_crypto_strings();
    
    // 默认值
    g_conf.mode = MODE_UDP;
    strcpy(g_conf.remote_host, "127.0.0.1");
    g_conf.remote_port = 51820;
    g_conf.local_port = 10808;
    g_conf.token = 0x1122334455667788ULL;
    
    // 解析参数 (支持 -l -m -H -P --dns)
    for(int i=1; i<argc; i++) {
        if(!strcmp(argv[i], "-s") && i+1<argc) strcpy(g_conf.remote_host, argv[++i]);
        else if(!strcmp(argv[i], "-p") && i+1<argc) g_conf.remote_port = atoi(argv[++i]);
        else if(!strcmp(argv[i], "-l") && i+1<argc) g_conf.local_port = atoi(argv[++i]);
        else if(!strcmp(argv[i], "-t") && i+1<argc) g_conf.token = _strtoui64(argv[++i], NULL, 16);
        else if(!strcmp(argv[i], "-m") && i+1<argc) {
            if(!strcmp(argv[++i], "wss")) g_conf.mode = MODE_WSS;
        }
        else if(!strcmp(argv[i], "-H") && i+1<argc) strcpy(g_conf.ws_host, argv[++i]);
        else if(!strcmp(argv[i], "-P") && i+1<argc) strcpy(g_conf.ws_path, argv[++i]);
        else if(!strcmp(argv[i], "--dns1") && i+1<argc) strcpy(g_conf.dns1, argv[++i]);
        else if(!strcmp(argv[i], "--dns2") && i+1<argc) strcpy(g_conf.dns2, argv[++i]);
    }
    
    if (g_conf.mode == MODE_WSS && strlen(g_conf.ws_host) == 0) strcpy(g_conf.ws_host, g_conf.remote_host);

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(g_conf.local_port);
    
    bind(listen_sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(listen_sock, 20);
    
    printf("[Core] Listen %d | Mode: %s | Target: %s:%d\n", 
           g_conf.local_port, g_conf.mode == MODE_UDP ? "UDP" : "WSS",
           g_conf.remote_host, g_conf.remote_port);

    while(1) {
        SOCKET client = accept(listen_sock, NULL, NULL);
        if (client == INVALID_SOCKET) continue;
        
        worker_arg_t *arg = malloc(sizeof(worker_arg_t));
        arg->client = client;
        
        // 调度核心：根据 GUI 的指令选择线程
        if (g_conf.mode == MODE_UDP) _beginthreadex(NULL, 0, udp_worker, arg, 0, NULL);
        else _beginthreadex(NULL, 0, wss_worker, arg, 0, NULL);
    }
    
    return 0;
}
