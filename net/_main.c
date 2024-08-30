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

void hexdump2(const void *buf, int len) {
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

uint16_t read16be(const void *buf) {
    const uint8_t *p = (const uint8_t *)buf;
    return (p[0] << 8) | p[1];
}

uint32_t read32be(const void *buf) {
    const uint8_t *p = (const uint8_t *)buf;
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

void write16be(void *buf, uint16_t val) {
    uint8_t *p = (uint8_t *)buf;
    p[0] = val >> 8;
    p[1] = val;
}

void write32be(void *buf, uint32_t val) {
    uint8_t *p = (uint8_t *)buf;
    p[0] = val >> 24;
    p[1] = val >> 16;
    p[2] = val >> 8;
    p[3] = val;
}

void ptr2mac(uint8_t *buf, void *p) {
    intptr_t mac = (intptr_t)p;
    buf[0] = mac >> 40;
    buf[1] = mac >> 32;
    buf[2] = mac >> 24;
    buf[3] = mac >> 16;
    buf[4] = mac >> 8;
    buf[5] = mac;
}

int dump_packet(const uint8_t *buf, uint32_t size) {
    uint16_t ret = read16be(&buf[12]);
    if (ret == ETH_ARP) {
        printf("==== Packet (ARP) ====\n");
        hexadump(buf, size - 14);
    } else {
        printf("==== Packet ====\n");
        hexdump(buf, size - 14);
    }
    return ret;
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

extern void	dhcp_dump(void *, uint32_t);
extern int32_t udp_packet(
    void *, void *, int32_t, uint16_t, uint32_t, uint16_t, uint32_t, uint16_t);
extern void udp_hton(void *);
extern void ip_hton(void *);
extern uint16_t ipcksum(void *);
extern void eth_hton(void *);
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

    dhcp[0] = 2;                           // boot reply
    memcpy(dhcp + 1, msg + 1, 2);          // transaction ID
    memcpy(dhcp + 4, msg + 4, 4);          // xid
    write32be(dhcp + 16, next_ip);         // your IP
    memcpy(dhcp + 28, msg + 28, 16);       // client MAC
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

    // adjust packet: from `ip_out()`
    udp_hton(pktptr);
    ip_hton(pktptr);
    write16be(pktptr + 24, 0);  // checksum
    write16be(pktptr + 24, ipcksum(pktptr));  // checksum
    eth_hton(pktptr);

    // show packet
    hexdump2(pktptr, len);
    dump_packet(pktptr, len);
    printf("==== DHCP Reply ====\n");
    dhcp_dump(pktptr + (len - udp_len), udp_len);

    // send packet: from `netin()`
    eth_ntoh(pktptr);
    ip_in(pktptr);
}

int xinu_write(int did, const uint8_t *buf, uint32_t size) {
    printf("write(%d, %p, %u)\n", did, buf, size);
    hexdump2(buf, size);
    if (did == 2) {
        int eth_type = dump_packet(buf, size);
        if (eth_type == ETH_ARP && read16be(buf + 14) == 1) {
            reply_arp(buf);
        } else if (eth_type == ETH_IP) {
            const uint8_t *ip_header = buf + 14;
            int protocol = ip_header[9];
            printf("protocol: %d\n", protocol);
            if (protocol == 17) {  // UDP
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
            }
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

int xinu_control(int a, int b, intptr_t c, intptr_t d) {
    printf("control(%d, %d, %p, %p)\n", a, b, c, d);
    // ETHER0, ETH_CTRL_GET_MAC, (intptr)NetData.ethucast, 0
    if (a == 2 && b == 1) {
        ptr2mac((uint8_t *)c, &a);
        intptr_t mac = ((intptr_t)&a) & 0xffffffffffffL;
        printf("MAC addr => %p\n", mac);
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
#define ICMP_ECHOREQST 8
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

extern void net_init();
extern int getlocalip();
extern int dnslookup(const char *, uint32_t *);
extern int icmp_register(uint32_t);
extern int icmp_send(uint32_t, uint16_t, uint16_t, uint16_t, uint8_t *, int);
extern int icmp_release(int);

int main(int argc, char *argv[])
{
    int result;
    init_xinu();
    net_init();

    result = getlocalip();
    printf("getlocalip() => %p\n", result);

    const char *ips = "192.168.0.100";
    uint32_t ipaddr;
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
    uint8_t buf[56];
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
