/*
 * netif.c
 *
 *  Created on: Jul 18, 2017
 *      Author: haohd
 *
 *  Copyright (C) 2017 miniHome
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library.
 *  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <sys/time.h>
#include <lwip/prot/dhcp.h>
#include <lwip/apps/mdns.h>
#include "lwip.h"

extern char* w_pcap_lookupdev(char **errbuf);
extern void* w_pcap_open(char *dev, char *errbuf);
extern int w_pcap_next_ex(void *pcap, unsigned char **pkt_data);
extern void pcap_send(void *pcap, void *src, uint32_t size);

#define NET_DEBUG_PRINTF              printf
#define NETIF_SET_NAME(netif,c1,c2)   do { (netif)->name[0] = c1; (netif)->name[1] = c2; } while (0)
#define NET_IF_IP_LEN                 16
#define LOCALHOST_IP_ADDR             ((1 << 24) | (0 << 16) | (0 << 8) | (127)) /* "127.0.0.1" */

static err_t linux_lwip_init(struct netif *netif);
static err_t linux_link_output(struct netif *netif, struct pbuf *pfirst);
static u32_t get_default_getway_ip(void);
static void* netif_packet_capture(void *arg);

extern sys_mutex_t lock_tcpip_core;

#if LWIP_NETIF_STATUS_CALLBACK
static void linux_net_status_cb(struct netif *netif);
#endif
#if LWIP_IGMP
err_t linux_igmp_mac_filter(struct netif *netif, const ip4_addr_t *group,  u8_t action);
#endif


static struct netif my_netif;
static void *gppcap = NULL;
static u16_t available_ports[LWIP_LINUX_PORT_NUM*2];

struct netif* get_netif(void)
{
    return &my_netif;
}

int lwip_linux_check_port(u16_t port)
{
    int i;

    for (i = 0; i < LWIP_LINUX_PORT_NUM*2; i++)
    {
        if (port == available_ports[i])
        {
            return 1;
        }
    }

    /* port is not configured for LWIP */
    return 0;
}

static void srv_txt(struct mdns_service *service, void *txt_userdata)
{
    err_t res; 
    res = mdns_resp_add_service_txtitem(service, "path=/", 6);
    LWIP_ERROR("mdns add service txt failed\n", (res == ERR_OK), return);
}

extern char gerrbuf[];
err_t net_init(char *ifname)
{
    char cmd[256];
    u8_t mac_addr[6] = { 0x08, 0x00, 0x27, 0x90, 0x84, 0xd4 };
    char *errbuf = gerrbuf;
    char *dev = "enp0s3";
    int i;

    /* we will use DHCP, so ip addr will be overridden */
    /* 192.168.1.2 = 0x0201a8c0 or 0xc0a80116 */
    ip_addr_t ip = { 0x0201a8c0 };
    /* 192.168.1.1 */
    ip_addr_t gw = { 0x0101a8c0 };
    /* 255.255.255.0 */
    ip_addr_t mask = { 0x00ffffff };

    /* Disable firewall */
    system("sudo ufw disable");

    for (i = 0; i < LWIP_LINUX_PORT_NUM*2; i++)
    {
        /* Drop packets on ports */
        if (i < LWIP_LINUX_PORT_NUM)
        {
            available_ports[i] = LWIP_LINUX_SERVER_START_PORT_NUM + i;
        }
        else
        {
          available_ports[i] = LWIP_LINUX_CLIENT_START_PORT_NUM + (i - LWIP_LINUX_PORT_NUM);
        }
        sprintf(cmd, "sudo iptables -A INPUT -p tcp --destination-port %u -j DROP", available_ports[i]);
        system(cmd);
    }

    // Read MAC address from pre-programmed area of EEPROM.
    my_netif.hwaddr_len = 6;
    memcpy(&my_netif.hwaddr[0], mac_addr, 6);

    NET_DEBUG_PRINTF("MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
                my_netif.hwaddr[0], my_netif.hwaddr[1], my_netif.hwaddr[2],
                my_netif.hwaddr[3], my_netif.hwaddr[4], my_netif.hwaddr[5]);

    NET_DEBUG_PRINTF("IP  : %u.%u.%u.%u\n",
                (ip.addr) & 0xFF, (ip.addr >> 8) & 0xFF,
                (ip.addr >> 16) & 0xFF, (ip.addr >> 24) & 0xFF);

    NET_DEBUG_PRINTF("GW  : %u.%u.%u.%u\n",
                (gw.addr) & 0xFF, (gw.addr >> 8) & 0xFF,
                (gw.addr >> 16) & 0xFF, (gw.addr >> 24) & 0xFF);

    NET_DEBUG_PRINTF("MASK: %u.%u.%u.%u\n",
                (mask.addr) & 0xFF, (mask.addr >> 8) & 0xFF,
                (mask.addr >> 16) & 0xFF, (mask.addr >> 24) & 0xFF);

    NETIF_SET_NAME(&(my_netif), ' ', '1');

    my_netif.next = NULL;

#if NO_SYS
    // Initialize LWIP
    lwip_init();
#else
    // Initialize LWIP
    tcpip_init(NULL, NULL);
#endif

    // Add our netif to LWIP (netif_add calls our driver initialization function)
    if (netif_add(&my_netif,
                &ip,
                &mask,
                &gw,
                NULL,
                linux_lwip_init,
                ethernet_input) == NULL)
    {
            NET_DEBUG_PRINTF("netif_add failed\n");
            return ERR_IF;
    }

    netif_set_default(&my_netif);
    netif_set_link_down(&my_netif);
    netif_set_down(&my_netif);
#if LWIP_NETIF_STATUS_CALLBACK
    netif_set_status_callback(&my_netif, linux_net_status_cb);
#endif

    netif_set_up(&my_netif);

    NET_DEBUG_PRINTF("Initialized the lwip.\n");

    /* Start DHCP */
    dhcp_start(&my_netif);

#if LWIP_IGMP
    igmp_start(&my_netif);
#endif

    NET_DEBUG_PRINTF("before w_pcap_open.\n");
    /* open device for reading in promiscuous mode */
    gppcap = w_pcap_open(dev, errbuf);
    NET_DEBUG_PRINTF("after w_pcap_open.\n");
    if(gppcap == NULL)
    {
        printf("pcap_open_live(): %s\n", errbuf);
        return ERR_IF;
    }

    NET_DEBUG_PRINTF("before netif_set_link_up.\n");
    netif_set_link_up(&my_netif);
    printf("Lwip IF is up now!\n");

    // MDNS or mdns
    mdns_resp_init();
    mdns_resp_add_netif(&my_netif, "testlwip", 255);
    mdns_resp_add_service(&my_netif, "testlwip", "_http",
                           DNSSD_PROTO_TCP, 80, 3600, srv_txt, NULL);
}

void net_quit(void)
{
    char cmd[256];
    int i;

    /* Enable firewall */
    //system("sudo ufw enable");
    for (i = 0; i < LWIP_LINUX_PORT_NUM*2; i++)
    {
        /* Accept packets on ports */
        sprintf(cmd, "sudo iptables -A INPUT -p tcp --destination-port %u -j ACCEPT", available_ports[i]);
        system(cmd);
    }
}

pthread_t start_netif(void)
{
    pthread_t thread;

    int ret = pthread_create( &thread, NULL, netif_packet_capture, NULL);
    if(ret)
    {
        return -1;
    }

    return thread;
}

static void* netif_packet_capture(void *arg)
{
    int len;
    const unsigned char *pkt_data;
    unsigned char *pkt_data_cur;
    struct pbuf *pnew = NULL;
    struct pbuf *pCur;

    struct netif *mynetif = &my_netif;
    if (mynetif == NULL)
    {
      return NULL;
    }

    /* Read the packets */
    pkt_data = NULL;
    while((len = w_pcap_next_ex(gppcap, &pkt_data)) >= 0)
    {
#if 0 // KYLE test code
        /* Check link state, e.g. via MDIO communication with PHY */
        if(link_state_changed()) {
            if(link_is_up()) {
                netif_set_link_up(&my_netif);
            } else {
                netif_set_link_down(&my_netif);
            }
        }
#else
        struct dhcp *dhcp = netif_dhcp_data(&my_netif);
        switch(dhcp->state) {
            case DHCP_STATE_OFF:
printf("dhcp status : DHCP_STATE_OFF\n");
                break;
            case DHCP_STATE_INIT:
printf("dhcp status : DHCP_STATE_INIT\n");
                break;
            case DHCP_STATE_REQUESTING:
//printf("dhcp status : DHCP_STATE_REQUESTING\n");
                break;
            case DHCP_STATE_BOUND:
//printf("dhcp status : DHCP_BOUND\n");
                break;
            default:
                break;
        }
#endif

        if(len == 0 || pkt_data == NULL)
        {
            /* Timeout elapsed */
            continue;
        }

#if 0
printf("src %02x:%02x:%02x:%02x:%02x:%02x\n",
                pkt_data[0], pkt_data[1], pkt_data[2],
                pkt_data[3], pkt_data[4], pkt_data[5]);
printf("dst %02x:%02x:%02x:%02x:%02x:%02x\n",
                pkt_data[6], pkt_data[7], pkt_data[8],
                pkt_data[9], pkt_data[10], pkt_data[11]);
#endif

//printf("KYLE w_pcap_next_ex(%u)\n", len);

        if(len == 0 || pkt_data == NULL)
        {
            /* Timeout elapsed */
            continue;
        }

#if 0
printf("src %02x:%02x:%02x:%02x:%02x:%02x\n",
                pkt_data[0], pkt_data[1], pkt_data[2],
                pkt_data[3], pkt_data[4], pkt_data[5]);
printf("dst %02x:%02x:%02x:%02x:%02x:%02x\n",
                pkt_data[6], pkt_data[7], pkt_data[8],
                pkt_data[9], pkt_data[10], pkt_data[11]);
#endif

        if((pkt_data[0] == 0xff) && (pkt_data[1] == 0xff) &&
           (pkt_data[2] == 0xff) && (pkt_data[3] == 0xff) &&
           (pkt_data[4] == 0xff) && (pkt_data[5] == 0xff))
        {
            // datalink broadcast message
            // ARP
        }
        else if((pkt_data[0] == my_netif.hwaddr[0]) && (pkt_data[1] == my_netif.hwaddr[1]) &&
                (pkt_data[2] == my_netif.hwaddr[2]) && (pkt_data[3] == my_netif.hwaddr[3]) &&
                (pkt_data[4] == my_netif.hwaddr[4]) && (pkt_data[5] == my_netif.hwaddr[5]))
        {
        }
        else if((pkt_data[0] == 0x01) && (pkt_data[1] == 0x00) && (pkt_data[2] == 0x5e))
        {
        // multicast MAC address
#if 0
            printf("multicast eth frame\n");
            printf("dst %02x:%02x:%02x:%02x:%02x:%02x\n",
                    pkt_data[0], pkt_data[1], pkt_data[2],
                    pkt_data[3], pkt_data[4], pkt_data[5]);
            printf("src %02x:%02x:%02x:%02x:%02x:%02x\n",
                    pkt_data[6], pkt_data[7], pkt_data[8],
                    pkt_data[9], pkt_data[10], pkt_data[11]);
#endif
        }
        else
        {
            continue;
        }

	sys_mutex_lock(&lock_tcpip_core);
#if 0
        /* PBUF_RAM: pbuf are dynamically allocated from a contiguous memory area. The PBUF_RAM allocation is
         * slower than the PBUF_POOL and can lead to memory fragmentation. */
        pnew = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
        if (pnew != NULL)
        {
            memcpy(pnew->payload, pkt_data, len);

            mynetif->input(pnew, mynetif);
        }
        else
        {
        }
#else
	/* PBUF_POOL: a number of PBUb_POOL_SIZE pbufs are statically pre allocated with a fixed size of
         * PBUF_POOL_BUFSIZE (defined in the lwIP configuration file). This is the pbuf type used for packet reception
         * as it provides the fastest allocation.
         * PBUF_POOL_BUFSIZE: 1514 */
        {	
            unsigned int left;
            unsigned int copy_len;

            pnew = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
	    // check pnew

	    left = len;
	    pCur = pnew;
	    while ((left > 0) && (pCur != NULL)) {
                if(left <= PBUF_POOL_BUFSIZE) {
                    copy_len = left;
		} else {
                    copy_len = PBUF_POOL_BUFSIZE;
		}

		pCur->len = copy_len;
                memcpy(pCur->payload, pkt_data, copy_len);
		pkt_data += copy_len;
		left -= copy_len;

		pCur = pCur->next;
	    }
	}

	pnew->tot_len = len;
        mynetif->input(pnew, mynetif);
#endif
	sys_mutex_unlock(&lock_tcpip_core);

        // mdns works with timer tasks
        // Check lwIP timeouts.
	// arp announcement
        // sys_check_timeouts();
    }

    return NULL;
}

static err_t linux_lwip_init(struct netif *netif)
{
    // Setup lwIP arch interface.
    netif->output = etharp_output;
    netif->linkoutput = linux_link_output;
    netif->mtu = 1500;
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET | NETIF_FLAG_IGMP;
    netif->input = ethernet_input;
#if LWIP_IGMP
    netif->igmp_mac_filter = linux_igmp_mac_filter;
#endif // LWIP_IGMP
    return ERR_OK;
}

#if LWIP_NETIF_STATUS_CALLBACK
static void linux_net_status_cb(struct netif *netif)
{
}
#endif

#define netif_out_dbg(x) (void) 0
static err_t linux_link_output(struct netif *netif, struct pbuf *pfirst)
{
    /* Source location in pbuf payload for streamout.l/memcpy.b */
    register u32_t *src;
    /* Destination location in pbuf payload for memcpy.b */
    register u8_t *dest;
    /* Register used to pass the size of the payload to streamout.l/memcpy.b */
    register u32_t size;

    /* Current pbuf when combining pbufs. */
    struct pbuf *pcur;
    /* New pbuf as destination of combined pbufs. */
    struct pbuf *pnew;
    /* Total length of new pbuf payload. */
    u32_t tot_len;
    int ret;

    /* To support pbuf chains when sending the loop is used to add
     * multiple pbuf payloads into the transmit buffer. When the packet has
     * been formed then it can be transmitted. The tot_len and len members
     * of the pbuf structure determine whether a pbuf is a partial packet.
     */
    do
    {
        /* Each packet has 2 free bytes at the start of the first
         * pbuf in the chain. This is primarily to align the payload
         * to a 32 bit boundary. It works well for us as we can have
         * an aligned buffer to stream into the ethernet transmit
         * buffer directly.
         * The payload of the first pbuf has a word free (ARCH_HW_HLEN)
         * where the packet length word is written.
         */

#if 0
        /* Calculate Ethernet frame length. This is the total size of the
         * packet minus the length of the ethernet headers and the
         * packet length word. */
        *((u16_t *)pfirst->payload) = pfirst->tot_len - ETHERNET_WRITE_HEADER - ARCH_HW_HLEN;
#endif

        /* Stream out the payloads from each pbuf in the chain.
         * Start at the first.
         */
        pcur = pfirst;

        /* Holder for an aligned pbuf. If the length of the payload of a
         * pbuf is not a multiple of 4 bytes then it cannot be streamed into
         * the transmit buffer as the buffer requires 32-bit accesses.
         * Therefore anything other than aligned writes will result in gaps
         * in the data between pbuf payloads! */
        pnew = NULL;

        /* Iterate trough the pbuf chain. */
        while (1) {
            /* Setup registers for stream instruction.
             * Source data is the start of the pbuf payload. */
            src = (u32_t*)pcur->payload;
            /* Size is the length of this pbuf'f payload. */
            size = pcur->len;

            // printf("arch_ft900_link_output: pbuf chain size %u %p\n", size, src);

            /* If the length of pbuf is not a multiple of 4 it cannot be streamed.
             * The ETH_DATA register will only receive 32-bit writes correctly.
             */

            ret = pcap_sendpacket(gppcap, (u8_t *) src, size);

            /* Hard end of chain detected - catch this case. */
            if (pcur->next == NULL) {
                break;
            }

            /* Move to next pbuf in chain. */
            pcur = pcur->next;
        }

        // Move to next packet in chain. There probably isn't one.
        pfirst = pcur->next;
    } while (pfirst != NULL);

    return 0;
}

#if LWIP_IGMP
err_t linux_igmp_mac_filter(struct netif *netif, const ip4_addr_t *group,  u8_t action)
{
    return ERR_OK;
}
#endif

static u32_t get_default_getway_ip(void)
{
    FILE *f;
    char line[100] , *p , *c, *g, *saveptr;
    u32_t gw = 0;

    f = fopen("/proc/net/route" , "r");
    if (f == NULL) {
        return 0;
    }

    while(fgets(line , 100 , f)) {
        p = strtok_r(line , " \t", &saveptr);
        c = strtok_r(NULL , " \t", &saveptr);
        g = strtok_r(NULL , " \t", &saveptr);

        if(p != NULL && c != NULL) {
            if(strcmp(c , "00000000") == 0) {
                if (g) {
                    char *pEnd;
                    gw = (u32_t) strtol(g, &pEnd, 16);
                }
                break;
            }
        }
    }

    fclose(f);

    return gw;
}
