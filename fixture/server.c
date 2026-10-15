/*
 * fixture/server.c - migration target for shaar-lite.
 *
 * A minimal TLS 1.3 server, linked against OpenSSL 3.5, that still pins its
 * key exchange to a classical group. Upgrading the library does not change
 * this: the group list below overrides OpenSSL's post-quantum defaults.
 *
 * Usage: server <port> <cert.pem> <key.pem>
 * Prints "READY" on stdout once listening, then serves connections until
 * it is terminated.
 */
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static SSL_CTX *make_ctx(const char *cert, const char *key)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL)
        return NULL;
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1)
        goto fail;
    /* Key exchange profile: pinned to NIST P-256 for a legacy compliance requirement. */
    if (SSL_CTX_set1_groups_list(ctx, "P-256") != 1)
        goto fail;
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1)
        goto fail;
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1)
        goto fail;
    return ctx;
fail:
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s <port> <cert.pem> <key.pem>\n", argv[0]);
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);

    SSL_CTX *ctx = make_ctx(argv[2], argv[3]);
    if (ctx == NULL)
        return 1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)atoi(argv[1]));
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0 || listen(fd, 8) < 0) {
        perror("bind/listen");
        return 1;
    }
    printf("READY\n");
    fflush(stdout);

    for (;;) {
        int conn = accept(fd, NULL, NULL);
        if (conn < 0)
            continue;
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, conn);
        if (SSL_accept(ssl) == 1) {
            const char *group = SSL_get0_group_name(ssl);
            fprintf(stderr, "server: handshake ok, group=%s\n", group ? group : "(none)");
            SSL_write(ssl, "hello\n", 6);
            SSL_shutdown(ssl);
        } else {
            ERR_print_errors_fp(stderr);
        }
        SSL_free(ssl);
        close(conn);
    }
}
