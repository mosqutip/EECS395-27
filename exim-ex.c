#include <stdlib.h>
#include <stdio.h>

#define TRUE 1
#define FALSE 0

#define GNUTLS_CERT_INVALID 0xa
#define GNUTLS_CERT_REVOKED 0xFFFFFFFFU
#define VERIFY_REQUIRED 0x555
#define GNUTLS_AL_FATAL 0x001
#define GNUTLS_A_BAD_CERTIFICATE 0x002

typedef struct {
    int session;
    int peer_cert_verified;
    int verify_requirement;
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

int main(int argc, char *argv[]) {
    int rc;
    state_t *state = (state_t *)malloc(sizeof(state_t));
    int verify = atoi(argv[1]);
    char * error = NULL;


    rc = gnutls_certificate_verify_peers2(state->session, &verify);

    /* Handle the result of verification. INVALID seems to be set as well
       as REVOKED, but leave the test for both. */

    if ((rc < 0) || (verify & (GNUTLS_CERT_INVALID|GNUTLS_CERT_REVOKED)) != 0)
    {
        state->peer_cert_verified = FALSE;
        if (*error == NULL)
            *error = ((verify & GNUTLS_CERT_REVOKED) != 0) ? "revoked" : "invalid";

        /*
        DEBUG(D_tls)
            debug_printf("TLS certificate verification failed (%s): peerdn=%s\n",
                    *error, state->peerdn ? state->peerdn : US"<unset>");
                    */

        if (state->verify_requirement == VERIFY_REQUIRED)
        {
            gnutls_alert_send(state->session, GNUTLS_AL_FATAL, GNUTLS_A_BAD_CERTIFICATE);
            return FALSE;
        }
        /*
        DEBUG(D_tls)
            debug_printf("TLS verify failure overridden (host in tls_try_verify_hosts)\n");
            */
    }
    else
    {
        state->peer_cert_verified = TRUE;
        /*
        DEBUG(D_tls) debug_printf("TLS certificate verified: peerdn=%s\n",
                state->peerdn ? state->peerdn : US"<unset>");
                */
    }

    return 0;
}
