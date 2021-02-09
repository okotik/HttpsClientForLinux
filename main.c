#include <sys/socket.h>
#include <sys/time.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/* ---------------------------------------------------------- *
 * First we need to make a standard TCP socket connection.    *
 * create_socket() creates a socket & TCP-connects to server. *
 * ---------------------------------------------------------- */
/* ---------------------------------------------------------- *
 * create_socket() creates the socket & TCP-connect to server *
 * ---------------------------------------------------------- */
int create_socket(char url_str[], BIO *out) {
    int sockfd;
    char hostname[256] = "";
    char    portnum[6] = "443";
    char      proto[6] = "";
    char      *tmp_ptr = NULL;
    int           port;
    struct hostent *host;
    struct sockaddr_in dest_addr;

    /* ---------------------------------------------------------- *
   * Remove the final / from url_str, if there is one           *
   * ---------------------------------------------------------- */
    if(url_str[strlen(url_str)] == '/')
        url_str[strlen(url_str)] = '\0';

    /* ---------------------------------------------------------- *
   * the first : ends the protocol string, i.e. http            *
   * ---------------------------------------------------------- */
    strncpy(proto, url_str, (strchr(url_str, ':')-url_str));

    /* ---------------------------------------------------------- *
   * the hostname starts after the "://" part                   *
   * ---------------------------------------------------------- */
    strncpy(hostname, strstr(url_str, "://")+3, sizeof(hostname));

    /* ---------------------------------------------------------- *
   * if the hostname contains a colon :, we got a port number   *
   * ---------------------------------------------------------- */
    if(strchr(hostname, ':')) {
        tmp_ptr = strchr(hostname, ':');
        /* the last : starts the port number, if avail, i.e. 8443 */
        strncpy(portnum, tmp_ptr+1,  sizeof(portnum));
        *tmp_ptr = '\0';
    }

    port = atoi(portnum);

    if ( (host = gethostbyname(hostname)) == NULL ) {
        BIO_printf(out, "Error: Cannot resolve hostname %s.\n",  hostname);
        abort();
    }

    /* ---------------------------------------------------------- *
   * create the basic TCP socket                                *
   * ---------------------------------------------------------- */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    dest_addr.sin_family=AF_INET;
    dest_addr.sin_port=htons(port);
    dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);

    /* ---------------------------------------------------------- *
   * Zeroing the rest of the struct                             *
   * ---------------------------------------------------------- */
    memset(&(dest_addr.sin_zero), '\0', 8);

    tmp_ptr = inet_ntoa(dest_addr.sin_addr);

    /* ---------------------------------------------------------- *
   * Try to make the host connect here                          *
   * ---------------------------------------------------------- */
    if ( connect(sockfd, (struct sockaddr *) &dest_addr,
                 sizeof(struct sockaddr)) == -1 ) {
        BIO_printf(out, "Error: Cannot connect to host %s [%s] on port %d.\n",
                   hostname, tmp_ptr, port);
    }

    return sockfd;
}

static void parseResponse(char *rawResponse)
{
    unsigned long timestamp1 = 0;
    unsigned long timestamp2 = 0;
    struct timeval timer_usec;
      gettimeofday(&timer_usec, NULL);
        timestamp1 = ((unsigned long) timer_usec.tv_sec) * 1000000ll +
                            (unsigned long) timer_usec.tv_usec;

    char *bidArray = 0;
    char *askArray = 0;
    char timestamp[17];
    char parsedResponse[1024];

    for (unsigned long n=0 ; n<strlen(rawResponse); n++)
        if (!strncmp (&rawResponse[n],"bids",strlen("bids")))
        {
          rawResponse += n + 6;
          break;
        }

    for (unsigned long n=0 ; n<strlen(rawResponse); n++)
        if (!strncmp (&rawResponse[n],"]],",strlen("]],")))
        {
            bidArray = (char*)malloc(n);
          memcpy(bidArray, rawResponse, n+3);
          rawResponse += n + 3;
          break;
        }

    for (unsigned long n=0 ; n<strlen(rawResponse); n++)
        if (!strncmp (&rawResponse[n],"asks",strlen("asks")))
        {
          rawResponse += n + 6;
          break;
        }

    for (unsigned long n=0 ; n<strlen(rawResponse); n++)
        if (!strncmp (&rawResponse[n],"]]},",strlen("]]},")))
        {
            askArray = (char*)malloc(n);
          memcpy(askArray, rawResponse, n+2);
          rawResponse += n + 36;
          break;
        }

    memcpy(timestamp, rawResponse, 17);
    timestamp[16] = 0;

    gettimeofday(&timer_usec, NULL);
      timestamp2 = ((unsigned long) timer_usec.tv_sec) * 1000000ll +
                          (unsigned long) timer_usec.tv_usec;

      sprintf(parsedResponse, "{\"timestamp\":%s,\"timestamp1\":%lu,\"timestamp2\":%lu,\"bids\":%s\"asks\":%s}",
              timestamp, timestamp1, timestamp2, bidArray, askArray);

      int fd;
      if((fd = open("/media/sf_mission/server/response.log", O_CREAT| O_WRONLY | O_APPEND,0644)) >= 0) {
          write(fd,parsedResponse,strlen(parsedResponse));
          write(fd,"\n",1);
          close(fd);
      }

    if(bidArray)
        free(bidArray);
    if(askArray)
        free(askArray);
}

int main() {
    char acClientRequest[1024] = "GET /api/v2/public/get_order_book?instrument_name=BTC-12FEB21 HTTP/1.1\r\nHost: test.deribit.com\r\n\r\n";
    char buf[8196];
    int bytes;
    char           dest_url[] = "https://test.deribit.com";
    BIO              *certbio = NULL;
    BIO               *outbio = NULL;
    X509                *cert = NULL;
    X509_NAME       *certname = NULL;
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL *ssl;
    int server = 0;
    int ret, i;

    /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
    certbio = BIO_new(BIO_s_file());
    outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

    /* ---------------------------------------------------------- *
   * initialize SSL library and register algorithms             *
   * ---------------------------------------------------------- */
    if(SSL_library_init() < 0)
        BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");

    /* ---------------------------------------------------------- *
   * Set SSLv2 client hello, also announce SSLv3 and TLSv1      *
   * ---------------------------------------------------------- */
    method = SSLv23_client_method();

    /* ---------------------------------------------------------- *
   * Try to create a new SSL context                            *
   * ---------------------------------------------------------- */
    if ( (ctx = SSL_CTX_new(method)) == NULL)
        BIO_printf(outbio, "Unable to create a new SSL context structure.\n");

    /* ---------------------------------------------------------- *
   * Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
   * ---------------------------------------------------------- */
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    /* ---------------------------------------------------------- *
   * Create new SSL connection state object                     *
   * ---------------------------------------------------------- */
    ssl = SSL_new(ctx);

    /* ---------------------------------------------------------- *
   * Make the underlying TCP socket connection                  *
   * ---------------------------------------------------------- */
    server = create_socket(dest_url, outbio);
    if(server != 0)
        BIO_printf(outbio, "Successfully made the TCP connection to: %s.\n", dest_url);

    /* ---------------------------------------------------------- *
   * Attach the SSL session to the socket descriptor            *
   * ---------------------------------------------------------- */
    SSL_set_fd(ssl, server);

    /* ---------------------------------------------------------- *
   * Try to SSL-connect here, returns 1 for success             *
   * ---------------------------------------------------------- */
    if ( SSL_connect(ssl) != 1 )
        BIO_printf(outbio, "Error: Could not build a SSL session to: %s.\n", dest_url);
    else
        BIO_printf(outbio, "Successfully enabled SSL/TLS session to: %s.\n", dest_url);

    /* ---------------------------------------------------------- *
   * Get the remote certificate into the X509 structure         *
   * ---------------------------------------------------------- */
    cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL)
        BIO_printf(outbio, "Error: Could not get a certificate from: %s.\n", dest_url);
    else
        BIO_printf(outbio, "Retrieved the server's certificate from: %s.\n", dest_url);

    /* ---------------------------------------------------------- *
   * extract various certificate information                    *
   * -----------------------------------------------------------*/
    certname = X509_NAME_new();
    certname = X509_get_subject_name(cert);

    /* ---------------------------------------------------------- *
   * display the cert subject here                              *
   * -----------------------------------------------------------*/
    BIO_printf(outbio, "Displaying the certificate subject data:\n");
    X509_NAME_print_ex(outbio, certname, 0, 0);
    BIO_printf(outbio, "\n");

    SSL_write(ssl,acClientRequest, strlen(acClientRequest));   /* encrypt & send message */
    bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
    buf[bytes] = 0;
    printf("Received: \"%s\"\n", buf);

    parseResponse(buf);

    /* ---------------------------------------------------------- *
   * Free the structures we don't need anymore                  *
   * -----------------------------------------------------------*/
    SSL_free(ssl);
    close(server);
    X509_free(cert);
    SSL_CTX_free(ctx);
    BIO_printf(outbio, "Finished SSL/TLS connection with server: %s.\n", dest_url);
    return(0);
}
