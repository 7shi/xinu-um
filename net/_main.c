#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>

#define ETH_ARP 0x0806

extern void hexdump(const char *, int);
extern void hexadump(const char *, int);

void hexdump2(const char *buf, int len) {
    int i, f;
    const unsigned char *b = buf;
    printf("==== Dump ====\n");
    for (i = 0; i < len; i++, b++) {
        if (i) printf(i & 15 ? " " : "\n");
        printf("%02x", *b);
    }
    printf("\n");
}

unsigned short read16be(const void *buf) {
    unsigned char *p = (unsigned char *)buf;
    return (p[0] << 8) | p[1];
}

unsigned read32be(const void *buf) {
    unsigned char *p = (unsigned char *)buf;
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

int dump_packet(const char *buf, int size) {
    int ret = read16be(&buf[12]);
    if (ret == ETH_ARP) {
        printf("==== Packet (ARP) ====\n");
        hexadump(buf, size);
    } else {
        printf("==== Packet ====\n");
        hexdump(buf, size);
    }
    return ret;
}

int xinu_read(int did, char *buf, unsigned size) {
    printf("read(%d, %p, %u)\n", did, buf, size);
    return 0;
}

int xinu_write(int did, char *buf, unsigned size) {
    printf("write(%d, %p, %u)\n", did, buf, size);
    hexdump2(buf, size);
    if (did == 2) dump_packet(buf, size);
    return 0;
}

int disable() {
    static int id = 0;
    int ret = ++id;
    printf("disable() => %d\n", ret);
    return ret;
}

int restore(int mask) {
    printf("restore(%d)\n", mask);
}

int kprintf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

int mkbufpool(int bufsiz, int count)
{
    printf("mkbufpool(%d, %d)\n", bufsiz, count);
    return bufsiz;
}

void *getbuf(int bufsiz) {
    void *ret = malloc(bufsiz);
    printf("getbuf(%d) => %p\n", bufsiz, ret);
    return ret;
}

void xinu_freebuf(void *p) {
    printf("freebuf(%p)\n", p);
    free(p);
}

void panic(const char *s) {
    printf("%s\n", s);
    exit(1);
}

int recvclr() {
    printf("recvclr()\n");
    return 0;
}

int recvtime(int ms) {
    printf("recvtime(%d)\n", ms);
    return 0;
}

int currpid = 1;

void resched_cntl(int t) {
    printf("resched_cntl(%d)\n", t);
}

#define SEMSLEN 16
static int sems[SEMSLEN];
static int cursem = 0;

int semcreate(int count) {
    int ret = -1;
    if (cursem < SEMSLEN) {
        sems[ret = cursem++] = count;
    }
    printf("semcreate(%d) => %d\n", count, ret);
    return ret;
}

int xinu_semcount(int semid) {
    int ret = sems[semid];
    printf("semcount(%d) => %d\n", semid, ret);
    return ret;
}

int getticks() {
    int ret;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    ret = tv.tv_usec;
    printf("getticks() => %d\n", ret);
    return ret;
}

static int lastpid = 0;

int create(
    void      *funcaddr,  /* Address of the function  */
    unsigned  ssize,      /* Stack size in bytes      */
    short     priority,   /* Process priority > 0     */
    char      *name,      /* Name (for debugging)     */
    unsigned  nargs,      /* Number of args that follow   */
    ...) {
    int ret = ++lastpid;
    printf("create(%p, %d, %d, \"%s\", %d) => %d\n", funcaddr, ssize, priority, name, nargs, ret);
    return ret;
}

void xinu_resume(int id) {
    printf("resume(%d)\n", id);
}

int xinu_control(int a, int b, long c, long d) {
    printf("control(%d, %d, %p, %p)\n", a, b, c, d);
    // ETHER0, ETH_CTRL_GET_MAC, (intptr)NetData.ethucast, 0
    if (a == 2 && b == 1) {
        long mac = ((long)&a) & 0xffffffffffffL;
        memcpy((void *)c, &mac, 6);
        printf("MAC addr => %p\n", mac);
    }
    return 0;
}

int xinu_send(int pid, unsigned msg) {
    printf("send(%d, %u)\n", pid, msg);
    return 0;
}

int xinu_wait(int sid) {
    printf("wait(%d)\n", sid);
    return 0;
}

int xinu_signal(int sid) {
    printf("signal(%d)\n", sid);
    return 0;
}

#define SYSERR (-1)
#define ICMP_ECHOREQST 8

extern void net_init();
extern int dnslookup(const char *, unsigned *);
extern int icmp_register(unsigned);
extern int icmp_send(unsigned, unsigned short, unsigned short, unsigned short, char *, int);
extern int icmp_release(int);

extern unsigned char NetData[48];

int main(int argc, char *argv[])
{
    int result;
    net_init();

    const char *myips = "192.168.0.81";
    unsigned myipaddr;
    result = dnslookup(myips, &myipaddr);
    printf("dnslookup(\"%s\", %p) => %d\n", myips, &myipaddr, result);
    memcpy(NetData, &myipaddr, 4);

    const char *ips = "192.168.0.100";
    unsigned ipaddr;
    result = dnslookup(ips, &ipaddr);
    printf("dnslookup(\"%s\", %p) => %d\n", ips, &ipaddr, result);
    printf("Pinging %d.%d.%d.%d\n",
            (ipaddr>>24)&0xff,
            (ipaddr>>16)&0xff,
            (ipaddr>>8)&0xff,
            (ipaddr)&0xff);

    /* Register to receive an ICMP Echo Reply */

    int slot = icmp_register(ipaddr);
    printf("icmp_register(%p) => %d\n", ipaddr, slot);
    if (slot == SYSERR) {
        fprintf(stderr,"%s: ICMP registration failed\n", ips);
        return 1;
    }

    /* Fill the buffer with values - start with low-order byte of   */
    /*  the sequence number and increment           */

    int seq = 0;
    int nextval = seq;
    char buf[56];
    for (int i = 0; i<sizeof(buf); i++) {
        buf[i] = 0xff & nextval++;
    }

    /* Send an ICMP Echo Request */
    int retval = icmp_send(ipaddr, ICMP_ECHOREQST, slot,
                    seq++, buf, sizeof(buf));
    if (retval == SYSERR) {
        fprintf(stderr, "%s: cannot send ping\n", ips);
        icmp_release(slot);
        return 1;
    }

    return 0;
}
