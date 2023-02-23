/*
    auto biu~
    bg4uvr@2023
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <ctype.h>
#include "unp.h"

char server[50], port[10], mycall[10], msg[256];

#define MAXLEN 512

char *filename(void)
{
    static char buf[50];
    time_t now = time(NULL);
    struct tm *timenow = localtime(&now);
    sprintf(buf, "%04d-%02d-%02d.log", timenow->tm_year + 1900, timenow->tm_mon, timenow->tm_mday);
    return buf;
}

char *timestr(void)
{
    static char buf[20];
    time_t now = time(NULL);
    struct tm *timenow = localtime(&now);
    sprintf(buf, "%02d:%02d:%02d", timenow->tm_hour, timenow->tm_min, timenow->tm_sec);
    return buf;
}

int kissdecode(uint8_t *outbuf, uint8_t *inbuf, uint16_t len)
{
    if (inbuf[0] != 0xc0 || inbuf[1] != 0x00 || inbuf[len - 1] != 0xc0)
    {
        printf("error, kiss frame flag check fail(0xc0,0x00 ... 0xc0)\n");
        return -1;
    }
    uint16_t in = 2, out = 0;
    while (in < len - 1)
    {
        if (inbuf[in] != 0xdb)
            outbuf[out++] = inbuf[in++];
        else
        {
            switch (inbuf[in + 1])
            {
            case 0xdc:
                outbuf[out++] == 0xc0;
                break;
            case 0xdd:
                outbuf[out++] == 0xdb;
                break;
            default:
                printf("error, kiss data have '0xdb,xx'\n");
                return -1;
                break;
            }
            in += 2;
        }
    }
    outbuf[out] = 0;
    return (out);
}

int kissencode(uint8_t *outbuf, uint8_t *inbuf, uint16_t len)
{
    uint16_t in = 0, out = 2;
    outbuf[0] = 0xc0;
    outbuf[1] = 0x00;
    while (in < len)
    {
        switch (inbuf[in])
        {
        case 0xc0:
            outbuf[out++] == 0xdb;
            outbuf[out++] == 0xdc;
            break;
        case 0xdb:
            outbuf[out++] == 0xdb;
            outbuf[out++] == 0xdd;
            break;
        default:
            outbuf[out++] = inbuf[in];
            break;
        }
        in++;
    }
    outbuf[out++] = 0xc0;
    return (out);
}

int uicall2str(uint8_t *outbuf, uint8_t *endflag, uint8_t *inbuf)
{
    uint8_t tmpbuf[10], i;
    memset(tmpbuf, 0, 10);
    memcpy(tmpbuf, inbuf, 6);
    for (i = 0; i < 6; i++)
        tmpbuf[i] >>= 1;
    while (tmpbuf[i - 1] == ' ')
        tmpbuf[--i] = 0;
    uint8_t ssid = ((inbuf[6] >> 1) - '0') & 0x0f;
    if (ssid > 0)
        sprintf(tmpbuf + strlen(tmpbuf), "-%d", ssid);
    if (inbuf[6] & 0x80)
        strcat(tmpbuf, "*");
    strcpy(outbuf, tmpbuf);
    if (inbuf[6] & 0x01)
        *endflag = 1;
    else
        *endflag = 0;
    return strlen(tmpbuf);
}

int decode(uint8_t *outbuf, uint8_t *inbuf, uint16_t len)
{
    uint8_t buf[MAXLEN];
    int16_t uilen = kissdecode(buf, inbuf, len);
    if (uilen < 16)
    {
        printf("error, uidecode uilen<16\n");
        return -1;
    }
    uint8_t endflag = 0, cnt = 0, sourceflag = 0;
    *outbuf = 0;
    uicall2str(outbuf + strlen(outbuf), &endflag, buf + 7);
    if (outbuf[strlen(outbuf) - 1] == '*')
        outbuf[strlen(outbuf) - 1] = 0;
    sourceflag = endflag;
    strcat(outbuf, ">");
    uicall2str(outbuf + strlen(outbuf), &endflag, buf);
    sprintf(outbuf + strlen(outbuf), ",");
    if (sourceflag == 0)
    {
        while (endflag == 0)
        {
            uicall2str(outbuf + strlen(outbuf), &endflag, buf + cnt * 7 + 14);
            strcat(outbuf, ",");
            if (++cnt > 8)
            {
                printf("error, UIframe route EndFlag not found.");
                return -1;
            }
        }
    }
    uint8_t *laststar = strrchr(outbuf, '*');
    if (laststar != NULL)
    {
        uint8_t i = 0, j = 0, starcnt = 0;
        for (; &outbuf[i] < laststar; i++)
            if (outbuf[i] != '*')
                outbuf[j++] = outbuf[i];
            else
                starcnt++;
        if (starcnt)
        {
            outbuf[j] = 0;
            strcat(outbuf, laststar);
        }
    }
    outbuf[strlen(outbuf) - 1] = ':';
    u_int16_t msglen = uilen - cnt * 7 - 16;
    uint8_t byte, tmpbuf[10];
    for (uint16_t i = 0; i < msglen; i++)
    {
        byte = buf[cnt * 7 + 16 + i];
        if (byte < 0x20 || byte > 0x7e)
            sprintf(tmpbuf, "<0x%02x>", byte);
        else
            sprintf(tmpbuf, "%c", byte);
        strcat(outbuf, tmpbuf);
    }
    return strlen(outbuf);
}

int str2uicall(uint8_t *outbuf, uint8_t *inbuf)
{
    uint8_t i, j, k;
    for (i = 0; i < 11; i++)
    {
        if (inbuf[i] == '>' || inbuf[i] == ',' || inbuf[i] == ':' || inbuf[i] == '*')
            break;
    }
    if (i == 11)
    {
        printf("[error] str2uicall: input call+ssid+flag > 10\n");
        return -1;
    }
    for (j = 0; j < i; j++)
    {
        if (inbuf[j] == '-')
            break;
    }
    if (j > 6)
    {
        printf("[error] str2uicall: call len > 6\n");
        return -1;
    }
    for (k = 0; k < j; k++)
        outbuf[k] = inbuf[k] << 1;
    while (k < 6)
        outbuf[k++] = 0x40;
    if (j == i)
        outbuf[k] = '0' << 1;
    else
    {
        switch (i - j)
        {
        case 2:
            outbuf[k] = inbuf[j + 1] << 1;
            break;
        case 3:
            outbuf[k] = inbuf[j + 2] + 10 << 1;
            break;
        default:
            printf("[error] str2uicall: ssid len fail.\n");
            break;
        }
    }
    if (inbuf[i] == '*')
    {
        outbuf[k] |= 0x80;
        i++;
    }
    if (inbuf[i] == ':')
        outbuf[k] |= 0x01;
    return ++i;
}

int encode(uint8_t *outbuf, uint8_t *inbuf)
{
    uint8_t buf[MAXLEN];
    memset(buf, 0, sizeof(buf));
    uint16_t ptr = 0;
    uint8_t routecnt = 0;
    ptr += str2uicall(buf + 7, inbuf);
    buf[13] |= 0x80;
    ptr += str2uicall(buf, inbuf + ptr);
    while (!(buf[6] & 0x01 || buf[13 + routecnt * 7] & 0x01))
    {
        ptr += str2uicall(buf + (routecnt + 2) * 7, inbuf + ptr);
        routecnt++;
        if (buf[13 + routecnt * 7] & 0x80)
            for (uint8_t i = 0; i < routecnt; i++)
                buf[13 + i * 7] |= 0x80;
    }
    buf[(routecnt + 2) * 7] = 0x03;
    buf[(routecnt + 2) * 7 + 1] = 0xf0;
    buf[(routecnt + 2) * 7 + 2] = 0;
    sprintf(buf + strlen(buf), "%s", inbuf + ptr);
    return kissencode(outbuf, buf, strlen(buf));
}

void Process(char *server, char *port)
{
    FILE *fp = NULL;
    uint8_t buffer[MAXLEN], dspbuf[MAXLEN], tmpbuf[100];
    u_int32_t starttime = 0, lasttime = 0;
    uint8_t workflag = 0, reptcnt = 0;
    fd_set rset;
    struct timeval tv;
    int r_fd, m, n, optval;
    socklen_t optlen = sizeof(optval);
    r_fd = Tcp_connect(server, port);
    setsockopt(r_fd, IPPROTO_TCP, TCP_NODELAY, &optval, optval);
    optval = 1;
    setsockopt(r_fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);
    optval = 3;
    setsockopt(r_fd, IPPROTO_TCP, TCP_KEEPCNT, &optval, optlen);
    optval = 60;
    setsockopt(r_fd, IPPROTO_TCP, TCP_KEEPIDLE, &optval, optlen);
    optval = 5;
    setsockopt(r_fd, IPPROTO_TCP, TCP_KEEPINTVL, &optval, optlen);
    printf("server connected.\n");
    while (1)
    {
        FD_ZERO(&rset);
        FD_SET(r_fd, &rset);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        m = Select(r_fd + 1, &rset, NULL, NULL, &tv);
        if (m > 0)
        {
            n = recv(r_fd, buffer, MAXLEN, 0);
            if (n == 0)
            {
                fprintf(stderr, "remote disconnect");
                exit(0);
            }
            if ((n < 0) && !(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN))
            {
                fprintf(stderr, "read from remote error: %d", errno);
                exit(0);
            }
            if (n > 0)
            {
                if (buffer[0] == 0xc0 && buffer[1] == 0x00 && buffer[n - 1] == 0xc0)
                {
                    fp = fopen(filename(), "a");
                    sprintf(tmpbuf, "[%s] kiss frame received:\n", timestr());
                    printf("%s", tmpbuf);
                    fprintf(fp, "%s", tmpbuf);
                    for (uint16_t i = 0; i < n; i++)
                    {
                        printf("%02X ", buffer[i]);
                        fprintf(fp, "%02X ", buffer[i]);
                    }
                    printf("\n");
                    fprintf(fp, "\n");
                    decode(dspbuf, buffer, n);
                    printf("%s\n", dspbuf);
                    fprintf(fp, "%s\n", dspbuf);
                    if (strstr(dspbuf, "RS0ISS*") != NULL || strstr(dspbuf, "RS0ISS>") != NULL)
                    {
                        if (workflag == 0 && time(NULL) - lasttime > 900)
                        {
                            reptcnt = 0;
                            starttime = time(NULL);
                            workflag = 1;
                            sprintf(tmpbuf, "work start...\n");
                            printf("%s", tmpbuf);
                            fprintf(fp, "%s", tmpbuf);
                        }
                    }
                    char callcheck[15];
                    sprintf(callcheck, "%s>", mycall);
                    if (workflag == 1 && strstr(dspbuf, callcheck) && strstr(dspbuf, "RS0ISS*"))
                    {
                        reptcnt++;
                        sprintf(tmpbuf, "my beacon recevied %d times.\n", reptcnt);
                        printf("%s", tmpbuf);
                        fprintf(fp, "%s", tmpbuf);
                        if (reptcnt >= 3)
                        {
                            sprintf(tmpbuf, "work stopped.\n");
                            printf("%s", tmpbuf);
                            fprintf(fp, "%s", tmpbuf);
                            workflag = 0;
                        }
                    }
                    fclose(fp);
                }
            }
        }
        if (workflag == 1)
        {
            if ((time(NULL) - lasttime) > 30)
            {
                fp = fopen(filename(), "a");
                sprintf(dspbuf, "%s>BEACON,RS0ISS:%s", mycall, msg);
                n = encode(buffer, dspbuf);
                Write(r_fd, buffer, n);
                lasttime = time(NULL);
                sprintf(tmpbuf, "[%s] beacon sent.\n", timestr());
                printf("%s", tmpbuf);
                fprintf(fp, "%s", tmpbuf);
                fclose(fp);
            }
            if ((time(NULL) - starttime) > 300)
            {
                fp = fopen(filename(), "a");
                sprintf(tmpbuf, "[%s] time over, work stopped.\n", timestr());
                printf("%s", tmpbuf);
                fprintf(fp, "%s", tmpbuf);
                fclose(fp);
                workflag = 0;
            }
        }
    }
    close(r_fd);
}

int main(int argc, char *argv[])
{
    printf("\n\t\t--------------\n\t\t|  AUTO BIU  |\n\t\t--------------\n");
    printf("\t\t\t by bg4uvr@qq.com\n");
    printf("\nyou can use './autobiu -d' to run as debug mode.\n\n");
    int debug = 0;
    if (argc == 2 && strcmp(argv[1], "-d") == 0)
        debug = 1;
    else if (argc != 1)
    {
        printf("\ncommand option fail, only can use '-d'\n\n");
        printf("\nnow the program exited.\n\n");
        return 0;
    }
    FILE *fp;
    fp = fopen("autobiu.conf", "r");
    if (fp == NULL)
    {
        fp = fopen("autobiu.conf", "w");
        fprintf(fp, "# autobiu.conf\n\nserver:\t127.0.0.1\nport:\t8001\nmycall:\tBG4UVR-6\n");
        fprintf(fp, "msg:\t!3153.34N/12106.91E`Nantong CHINA\n");
        printf("config file \"autobiu.conf\" not found, now created,\npelase edit it and run program again!\n\n");
        printf("now the program exited.\n\n");
        fclose(fp);
        return 0;
    }
    else
    {
        char buf[256];
        uint8_t confno = 0;
        char *head, *tail;
        while (fgets(buf, 256, fp) != NULL)
        {
            if (buf[0] == '#')
                continue;
            if (strstr(buf, "server:"))
                confno = 1;
            else if (strstr(buf, "port:"))
                confno = 2;
            else if (strstr(buf, "mycall:"))
                confno = 3;
            else if (strstr(buf, "msg:"))
                confno = 4;
            else
                continue;
            head = strchr(buf, ':');
            do
                head++;
            while (isspace(*head));
            tail = head;
            if (confno != 4)
            {
                do
                    tail++;
                while (!isspace(*tail));
            }
            else
            {
                do
                    tail++;
                while (*tail != '\n');
            }
            *tail = 0;
            switch (confno)
            {
            case 1:
                strcpy(server, head);
                break;
            case 2:
                strcpy(port, head);
                break;
            case 3:
                strcpy(mycall, head);
                break;
            case 4:
                strcpy(msg, head);
                break;
            }
        }
        fclose(fp);
    }
    printf("config file read success:\n\tserver:\t%s\n\tport:\t%s\n\tmycall:\t%s\n\tmsg:\t%s\n", server, port, mycall, msg);
    if (debug == 0)
    {
        printf("\nprogram now run as daemon mode(in background), now\nyou can safe logout or disconnect SSH.\n\n");
        printf("if you want to stop it, use command: 'pkill autobiu'\n\n");
    }
    signal(SIGCHLD, SIG_IGN);
    if (debug == 0)
    {
        daemon_init(argv[0], LOG_DAEMON);
        while (1)
        {
            int pid;
            pid = fork();
            if (pid == 0)
                break;
            else if (pid == -1)
                exit(0);
            else
            {
                wait(NULL);
            }
            sleep(2);
        }
    }
    Process(server, port);
    return (0);
}
