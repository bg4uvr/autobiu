/*
    auto biu~
    bg4uvr@2023
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <linux/limits.h>
#include <libgen.h>
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

char server_kiss[50], port_kiss[10], server_aprs[50], port_aprs[10], mycall[10], msg[256];

#define MAXLEN 512

char *filename(void)
{
    static char buf[50];
    time_t now = time(NULL);
    struct tm *timenow = localtime(&now);
    sprintf(buf, "%04d-%02d-%02d.log", timenow->tm_year + 1900, timenow->tm_mon + 1, timenow->tm_mday);
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
    char buf[MAXLEN];
    int16_t uilen = kissdecode(buf, inbuf, len);
    if (uilen < 16)
    {
        printf("error, uidecode uilen<16\n");
        return -1;
    }
    buf[uilen] = 0;
    char *ax25chk = strstr(buf, "\x03\xf0");
    if (ax25chk == NULL || (ax25chk - buf) % 7 != 0 || (ax25chk - buf < 14) || (ax25chk - buf) > 70)
        return sprintf(outbuf, "not AX.25 format data");
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

void Process()
{
    FILE *fp = NULL;
    uint8_t buffer[MAXLEN], dspbuf[MAXLEN], tmpbuf[100], callcheck[15], routecheck[15];
    u_int32_t starttime = 0, lasttime = 0;
    uint8_t workflag = 0, login = 0;
    fd_set rset;
    struct timeval tv;
    int s_fd, i_fd = -1, max_fd, m, n, optval;
    socklen_t optlen = sizeof(optval);
    s_fd = Tcp_connect(server_kiss, port_kiss);
    i_fd = Tcp_connect(server_aprs, port_aprs);
    setsockopt(s_fd, IPPROTO_TCP, TCP_NODELAY, &optval, optval);
    setsockopt(i_fd, IPPROTO_TCP, TCP_NODELAY, &optval, optval);
    optval = 1;
    setsockopt(s_fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);
    setsockopt(i_fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);
    optval = 3;
    setsockopt(s_fd, IPPROTO_TCP, TCP_KEEPCNT, &optval, optlen);
    setsockopt(i_fd, IPPROTO_TCP, TCP_KEEPCNT, &optval, optlen);
    optval = 60;
    setsockopt(s_fd, IPPROTO_TCP, TCP_KEEPIDLE, &optval, optlen);
    setsockopt(i_fd, IPPROTO_TCP, TCP_KEEPIDLE, &optval, optlen);
    optval = 5;
    setsockopt(s_fd, IPPROTO_TCP, TCP_KEEPINTVL, &optval, optlen);
    setsockopt(i_fd, IPPROTO_TCP, TCP_KEEPINTVL, &optval, optlen);
    printf("monitoring radio kiss data..\n");

    while (1)
    {
        FD_ZERO(&rset);
        FD_SET(s_fd, &rset);
        FD_SET(i_fd, &rset);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        max_fd = max(s_fd, i_fd);
        m = Select(max_fd + 1, &rset, NULL, NULL, &tv);
        if (m > 0)
        {
            if (FD_ISSET(s_fd, &rset))
            {
                n = recv(s_fd, buffer, MAXLEN, 0);
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
                        if (workflag == 0 && time(NULL) - lasttime > 900)
                        {
                            if (
                                strstr(dspbuf, "RS0ISS*") || strstr(dspbuf, "RS0ISS>") ||
                                strstr(dspbuf, "NA1SS*") || strstr(dspbuf, "NA1SS>") ||
                                strstr(dspbuf, "APRSAT*") || strstr(dspbuf, "APRSAT>") ||
                                strstr(dspbuf, "AISAT*") || strstr(dspbuf, "AISAT>") ||
                                strstr(dspbuf, "ARISS*") || strstr(dspbuf, "ARISS>") ||
                                strstr(dspbuf, "PCSAT-1*") || strstr(dspbuf, "PCSAT-1>") ||
                                strstr(dspbuf, "PSAT*") || strstr(dspbuf, "PSAT>") ||
                                strstr(dspbuf, "SGATE*") || strstr(dspbuf, "SGATE>") ||
                                strstr(dspbuf, "A55BTN*") || strstr(dspbuf, "A55BTN>"))
                            {
                                sprintf(tmpbuf, "ISS or Sat signal has been received. task start..\n");
                                printf("%s", tmpbuf);
                                fprintf(fp, "%s", tmpbuf);
                                starttime = time(NULL);
                                workflag = 1;
                            }
                        }
                        fclose(fp);
                    }
                }
            }
            if (FD_ISSET(i_fd, &rset))
            {
                n = recv(i_fd, buffer, MAXLEN, 0);
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
                    if (login == 0 && (strstr(buffer, "aprsc") || strstr(buffer, "javAPRSSrvr")))
                    {
                        sprintf(dspbuf, "user %s pass -1 vers autodiu 1.0 filter b/%s\r\n", mycall, mycall);
                        Write(i_fd, dspbuf, strlen(dspbuf));
                        login = 1;
                    }
                    sprintf(callcheck, "%s>", mycall);
                    if (workflag == 1 && strstr(buffer, callcheck) && strstr(buffer, "RS0ISS*")) // we only check ISS, ignore other sat.
                    {
                        fp = fopen(filename(), "a");
                        sprintf(tmpbuf, "[%s] gating confirmed, task of this time is complete.\n", timestr());
                        printf("%s", tmpbuf);
                        fprintf(fp, "%s", tmpbuf);
                        workflag = 0;
                        fclose(fp);
                    }
                }
            }
        }
        if (workflag > 0)
        {
            if ((time(NULL) - lasttime) > 30)
            {
                fp = fopen(filename(), "a");
                sprintf(dspbuf, "%s>BEACON,ARISS,APRSAT:%s", mycall, msg);
                n = encode(buffer, dspbuf);
                srand(getpid() + time(0));
                usleep((rand() % 5000) * 1000);
                Write(s_fd, buffer, n);
                lasttime = time(NULL);
                sprintf(tmpbuf, "[%s] my beacon has been sent once.\n", timestr());
                printf("%s", tmpbuf);
                fprintf(fp, "%s", tmpbuf);
                fclose(fp);
            }
            if ((time(NULL) - starttime) > 480)
            {
                fp = fopen(filename(), "a");
                sprintf(tmpbuf, "[%s] time out, task of this time is stopped.\n", timestr());
                printf("%s", tmpbuf);
                fprintf(fp, "%s", tmpbuf);
                fclose(fp);
                workflag = 0;
            }
        }
    }
    close(s_fd);
    close(i_fd);
}

char *strupr(char *str)
{
    char *ptr = str;
    while (*ptr != '\0')
    {
        if (islower(*ptr))
            *ptr = toupper(*ptr);
        ptr++;
    }
    return str;
}

int checkcfg(void)
{
    FILE *fp;
    fp = fopen("autobiu.conf", "r");
    if (fp == NULL)
    {
        fp = fopen("autobiu.conf", "w");
        fprintf(fp, "# autobiu.conf\n\nserver_kiss:\t127.0.0.1\nport_kiss:\t8001\n");
        fprintf(fp, "server_aprs:\tasia.aprs2.net\nport_aprs:\t14580\nmycall:\t\tBG4UVR-6\n");
        fprintf(fp, "msg:\t\t!3153.34N/12106.91E`Nantong CHINA\n");
        printf("config file \"autobiu.conf\" not found, now created,\nplease edit it and run program again!\n\n");
        printf("now the program exited.\n\n");
        fclose(fp);
        return -1;
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
            if (strstr(buf, "server_kiss:"))
                confno = 1;
            else if (strstr(buf, "port_kiss:"))
                confno = 2;
            else if (strstr(buf, "server_aprs:"))
                confno = 3;
            else if (strstr(buf, "port_aprs:"))
                confno = 4;
            else if (strstr(buf, "mycall:"))
                confno = 5;
            else if (strstr(buf, "msg:"))
                confno = 6;
            else
                continue;
            head = strchr(buf, ':');
            do
                head++;
            while (isspace(*head));
            tail = head;
            if (confno != 6)
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
                strcpy(server_kiss, head);
                break;
            case 2:
                strcpy(port_kiss, head);
                break;
            case 3:
                strcpy(server_aprs, head);
                break;
            case 4:
                strcpy(port_aprs, head);
                break;
            case 5:
                strcpy(mycall, strupr(head));
                break;
            case 6:
                strcpy(msg, head);
                break;
            }
        }
        fclose(fp);
        if (strlen(server_kiss) && strlen(port_kiss) && strlen(server_aprs) && strlen(port_aprs) && strlen(mycall) && strlen(msg))
        {
            printf("config file read success:\n\tserver_kiss:\t%s\n\tport_kiss:\t%s\n\tserver_aprs:\t%s\n\tport_aprs:\t%s\n\tmycall:\t\t%s\n\tmsg:\t\t%s\n",
                   server_kiss, port_kiss, server_aprs, port_aprs, mycall, msg);
            return 1;
        }
        else
        {
            printf("error, 'autodiu.confg' wrong, please check program exited!\n");
            return -1;
        }
    }
}

void chworkdir()
{
    char exePath[PATH_MAX];
    memset(exePath, 0, sizeof(exePath));
    readlink("/proc/self/exe", exePath, sizeof(exePath));
    char *exeDir = dirname(exePath);
    chdir(exeDir);
}

int main(int argc, char *argv[])
{
    int ret = system("echo $(pgrep autobiu) |grep -c \" \" > /dev/null");
    if (!ret)
    {
        printf("program already running, can't run it more than once.\n");
        return -1;
    }

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
        return -1;
    }
    chworkdir();
    if (checkcfg() < 0)
        return -1;
    if (debug == 0)
    {
        printf("\nprogram now run as daemon mode(in background), now\nyou can safe logout or disconnect SSH.\n\n");
        printf("if you want to stop it, use command: 'pkill autobiu'\n\n");
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
    Process();
    return (0);
}
