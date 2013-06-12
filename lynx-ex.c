#include <stdlib.h>
#include <stdio.h>

#define TRUE 1
#define FALSE 0

#define GNUTLS_CERT_INVALID 0xa
#define GNUTLS_CERT_REVOKED 0xFFFFFFFFU
#define VERIFY_REQUIRED 0x555
#define GNUTLS_AL_FATAL 0x001
#define GNUTLS_A_BAD_CERTIFICATE 0x002
#define GNUTLS_CERT_SIGNER_NOT_FOUND 0x003
#define GNUTLS_CERT_SIGNER_NOT_CA 0x004

typedef struct {
    int session;
    int peer_cert_verified;
    int verify_requirement;
    int gnutls_state;
} state_t;

int gnutls_certificate_verify_peers2(int s, int *i) {
    if (*i == 3) {
        return -1;
    } else {
        *i -= 1;
        return *i;
    }
}

void gnutls_alert_send(int s, int fatal, int bad) {
    printf("session %d had fatal %d and bad %d\n", s, fatal, bad);
}

char * gettext(char * in) {
    return in;
}

int main(int argc, char const* argv[])
{
    int ret;
    int tls_status;
    state_t *handle = (state_t *)malloc(sizeof(state_t));

    ret = gnutls_certificate_verify_peers2(handle->gnutls_state, &tls_status);
    if ((ret < 0) || tls_status) {
        int flag_continue = 1;
        char *msg2;

        if (tls_status & GNUTLS_CERT_SIGNER_NOT_FOUND) {
            msg2 = gettext("no issuer was found");
        } else if (tls_status & GNUTLS_CERT_SIGNER_NOT_CA) {
            msg2 = gettext("issuer is not a CA");
        } else if (tls_status & GNUTLS_CERT_SIGNER_NOT_FOUND) {
            msg2 = gettext("the certificate has no known issuer");
        } else if (tls_status & GNUTLS_CERT_REVOKED) {
            msg2 = gettext("the certificate has been revoked");
        } else {
            msg2 = gettext("the certificate is not trusted");
        }
    }

    return 0;
}
