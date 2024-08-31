#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#define ETH_ARP 0x0806
#define ETH_IP  0x0800

extern void hexdump(const uint8_t *, int);
extern void hexadump(const uint8_t *, int);

static void hexdump2(const void *buf, int len) {
    int i, f;
    const uint8_t *b = buf;
    printf("==== Dump ==== (0x%x)\n", len);
    for (i = 0; i < len; i++, b++) {
        int f = i & 15;
        if (i) printf(f ? " " : "\n");
        if (!f) printf("%04x: ", i);
        printf("%02x", *b);
    }
    printf("\n");
}

static uint16_t read16be(const void *buf) {
    const uint8_t *p = (const uint8_t *)buf;
    return (p[0] << 8) | p[1];
}

static uint32_t read32be(const void *buf) {
    const uint8_t *p = (const uint8_t *)buf;
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static void write16be(void *buf, uint16_t val) {
    uint8_t *p = (uint8_t *)buf;
    p[0] = val >> 8;
    p[1] = val;
}

static void write32be(void *buf, uint32_t val) {
    uint8_t *p = (uint8_t *)buf;
    p[0] = val >> 24;
    p[1] = val >> 16;
    p[2] = val >> 8;
    p[3] = val;
}

static void ptr2mac(uint8_t *buf, void *p) {
    intptr_t mac = (intptr_t)p;
    buf[0] = mac >> 40;
    buf[1] = mac >> 32;
    buf[2] = mac >> 24;
    buf[3] = mac >> 16;
    buf[4] = mac >> 8;
    buf[5] = mac;
}

static int dump_packet(const uint8_t *buf, uint32_t size) {
    uint16_t type = read16be(&buf[12]);
    if (type == ETH_ARP) {
        printf("==== Packet (ARP) ====\n");
        hexadump(buf, size - 14);
        return -1;
    } else if (type == ETH_IP) {
        int protocol = buf[23];
        printf("protocol: %d\n", protocol);
        if (protocol == 17) {  // UDP
            printf("==== Packet (UDP) ====\n");
            hexdump(buf, size - 14);
        }
        return protocol;
    }
    return 0;
}

int xinu_read(int did, uint8_t *buf, uint32_t size) {
    printf("read(%d, %p, %u)\n", did, buf, size);
    return 0;
}

extern void arp_packet(
    void *apkt, uint16_t op,
    void *dst_mac, uint32_t dst_ip,
    void *src_mac, uint32_t src_ip);
extern void arp_in(void *);

extern uint8_t NetData[48];

void reply_arp(const uint8_t *buf) {
    const int apkt_size = 42;
    uint8_t *apkt = malloc(apkt_size);
    uint8_t mac[6];
    ptr2mac(mac, apkt);
    arp_packet(apkt, 2, NetData + 33, *(uint32_t *)NetData, mac, read32be(buf + 0x26));
    hexdump2(apkt, apkt_size);
    dump_packet(apkt, apkt_size);
    arp_in(apkt);
}

#define IP_DHCP_SERVER 0xc0a80001 // 192.168.0.1
#define IP_POOL_START  0xc0a80051 // 192.168.0.81
#define IP_POOL_END    0xc0a80063 // 192.168.0.99

extern void ip_hton(void *);
extern uint16_t ipcksum(void *);
extern void eth_hton(void *);

static void adjust_packet(uint8_t *pktptr) {
    // from `ip_out()`
    ip_hton(pktptr);
    write16be(pktptr + 24, 0);  // checksum
    write16be(pktptr + 24, ipcksum(pktptr));  // checksum
    eth_hton(pktptr);
}

extern void	dhcp_dump(void *, uint32_t);
extern int32_t udp_packet(
    void *, void *, int32_t, uint16_t, uint32_t, uint16_t, uint32_t, uint16_t);
extern void udp_hton(void *);
extern void eth_ntoh(void *);
extern void ip_in(void *);

void reply_dhcp(const uint8_t *buf, const uint8_t *msg) {
    static uint32_t next_ip = IP_POOL_START;
    int p = 240, ot;
    uint8_t msgtype = 0, dhcptype = 5;
    while ((ot = msg[p]) != 255) {
        printf("p: %d, ot: %d\n", p, ot);
        if (ot == 53) msgtype = msg[p + 2];
        p += ot ? 2 + msg[p + 1] : 1;
    }

    if (msgtype == 1) {
        dhcptype = 2;
        printf("#### DHCP Offer ####\n");
    } else if (msgtype == 3) {
        printf("#### DHCP ACK ####\n");
    } else {
        printf("DHCP %d\n", msgtype);
    }

    uint8_t *dhcp = calloc(1, 512);

    dhcp[0] = 2;                        // boot reply
    memcpy(dhcp + 1, msg + 1, 2);       // transaction ID
    memcpy(dhcp + 4, msg + 4, 4);       // xid
    write32be(dhcp + 16, next_ip);      // your IP
    memcpy(dhcp + 28, msg + 28, 16);    // client MAC
    if (dhcptype == 5) {
        uint32_t ret = next_ip++;
        if (next_ip >= IP_POOL_END) next_ip = IP_POOL_START;
    }

    // set magic cookie
    uint8_t *options = dhcp + 236;
    memcpy(options, msg + 236, 4);  // magic cookie

    // set DHCP message type option
    options[4] = 53;        // option: DHCP message type
    options[5] = 1;         // length
    options[6] = dhcptype;  // DHCP offer or DHCP ACK

    // set subnet mask option
    options[7] = 1;     // option: subnet mask
    options[8] = 4;     // length
    write32be(options + 9, 0xffffff00);  // 255.255.255.0

    // set lease time option
    options[13] = 51;    // option: IP address lease time
    options[14] = 4;     // length
    write32be(options + 15, 24 * 60 * 60);  // 1 day in seconds

    // set server IP option
    options[19] = 54;    // option: server IP
    options[20] = 4;     // length
    write32be(options + 21, IP_DHCP_SERVER);

    // set terminator
    options[25] = 255;  // end of options

    // create UDP packet
    uint8_t *pktptr = calloc(1, 512);
    int udp_len = 236 + 26;
    int len = udp_packet(pktptr, dhcp, udp_len, 1, 0, 68, IP_DHCP_SERVER, 67);
    free(dhcp);
    memcpy(pktptr, pktptr + 6, 6);      // destination MAC address
    ptr2mac(pktptr + 6, reply_dhcp);    // source MAC address

    // adjust packet
    udp_hton(pktptr);   // from `ip_out()`
    adjust_packet(pktptr);

    // show packet
    hexdump2(pktptr, len);
    dump_packet(pktptr, len);
    printf("==== DHCP Reply ====\n");
    dhcp_dump(pktptr + (len - udp_len), udp_len);

    // send packet: from `netin()`
    eth_ntoh(pktptr);
    ip_in(pktptr);
}

extern uint8_t *icmp_mkpkt(
    uint32_t, uint16_t, uint16_t, uint16_t, const void *, int32_t);
extern void icmp_hton(void *);
extern uint16_t icmp_cksum(void *, int);

static void reply_icmp(const uint8_t *buf, int size) {
    uint32_t dstip = read32be(buf + 26);    // net_ipsrc
    uint32_t srcip = read32be(buf + 30);    // net_ipdst
    uint16_t ident = read16be(buf + 38);    // net_icident
    uint16_t seq   = read16be(buf + 40);    // net_icseq
    printf("dstip: %x, srcip: %x, ident: %x, seq: %x\n", dstip, srcip, ident, seq);
    uint8_t *pktptr = icmp_mkpkt(dstip, 0, ident, seq, buf + 42, size - 42);
    memcpy(pktptr, pktptr + 6, 6);  // destination MAC address
    memcpy(pktptr + 6, buf, 6);     // source MAC address
    *(uint32_t *)(pktptr + 26) = srcip;  // net_ipsrc

    // adjust packet
    icmp_hton(pktptr);  // from `ip_out()`
    write16be(pktptr + 36, 0);  // checksum
    write16be(pktptr + 36, icmp_cksum(pktptr + 34, size - 34));  // checksum
    adjust_packet(pktptr);

    // show packet
    hexdump2(pktptr, size);

    // send packet: from `netin()`
    eth_ntoh(pktptr);
    ip_in(pktptr);
}

int xinu_write(int did, const uint8_t *buf, uint32_t size) {
    printf("write(%d, %p, %u)\n", did, buf, size);
    hexdump2(buf, size);
    if (did == 2) {
        int type = dump_packet(buf, size);
        if (type == -1 && read16be(buf + 14) == 1) {
            reply_arp(buf);
        } else if (type == 17) {  // UDP
            const uint8_t *ip_header = buf + 14;
            const uint8_t *udp_header = ip_header + (ip_header[0] & 0xF) * 4;
            unsigned short src_port = read16be(udp_header);
            unsigned short dst_port = read16be(udp_header + 2);
            printf("src_port: %d, dst_port: %d\n", src_port, dst_port);
            const uint8_t *payload = udp_header + 8;
            if (src_port == 68 && dst_port == 67 && payload[0] == 1) {
                printf("==== DHCP Request ====\n");
                dhcp_dump((void *)payload, size - (payload - buf));
                reply_dhcp(buf, payload);
            }
        } else if (type == 1) {  // ICMP
            printf("==== ICMP Reply ====\n");
            reply_icmp(buf, size);
        }
    }
    return 0;
}

int disable() {
    static int id = 0;
    int ret = ++id;
    printf("disable() => %d\n", ret);
    return ret;
}

void restore(int mask) {
    printf("restore(%d)\n", mask);
}

int kprintf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vprintf(format, args);
    va_end(args);
    return ret;
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

int xinu_freebuf(void *p) {
    printf("freebuf(%p)\n", p);
    free(p);
    return 0;
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

int resched_cntl(int t) {
    printf("resched_cntl(%d)\n", t);
    return 0;
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

int64_t getticks() {
    int64_t ret;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    ret = tv.tv_usec;
    printf("getticks() => %lld\n", ret);
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

int xinu_resume(int id) {
    printf("resume(%d)\n", id);
    return 0;
}

int xinu_control(int a, int b, intptr_t c, intptr_t d) {
    printf("control(%d, %d, %p, %p)\n", a, b, (void *)c, (void *)d);
    // ETHER0, ETH_CTRL_GET_MAC, (intptr)NetData.ethucast, 0
    if (a == 2 && b == 1) {
        ptr2mac((uint8_t *)c, &a);
        intptr_t mac = ((intptr_t)&a) & 0xffffffffffffL;
        printf("MAC addr => %012lx\n", mac);
    }
    return 0;
}

int xinu_send(int pid, uint32_t msg) {
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
#define NPROC 2

struct {
    intptr_t prdesc[5];
} proctab[NPROC];

static void init_xinu() {
    for (int i = 0; i < NPROC; i++) {
        proctab[i].prdesc[0] = (intptr_t)stdin;
        proctab[i].prdesc[1] = (intptr_t)stdout;
        proctab[i].prdesc[2] = (intptr_t)stderr;
    }
}

static void ip_str(char *s, uint32_t ip) {
    snprintf(s, 16, "%d.%d.%d.%d",
        (ip >> 24) & 0xff,
        (ip >> 16) & 0xff,
        (ip >> 8) & 0xff,
        ip & 0xff);
}

extern void net_init();
extern int getlocalip();
extern int xsh_ping(int, char **);

int main(int argc, char *argv[])
{
    init_xinu();

    net_init();
    int ip = getlocalip();
    if (ip == SYSERR) {
        fprintf(stderr, "getlocalip() failed\n");
        return 1;
    }
    char ipaddr[16];
    ip_str(ipaddr, ip);
    printf("getlocalip() => %s\n", ipaddr);

    return xsh_ping(argc, argv);
}
