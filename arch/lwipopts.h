/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Simon Goldschmidt
 *
 */
#ifndef LWIP_HDR_LWIPOPTS_H
#define LWIP_HDR_LWIPOPTS_H

#define LWIP_LINUX        1
#define LWIP_DEBUG        1
#define lwip_linux_dbg(x) printf(x)

/* Prevent TLS error
 * Don't define LWIP_PROVIDE_ERRNO; lwip just check if it's defined or not.
 * If it's defined it provides its errno facilities.
 * #define LWIP_PROVIDE_ERRNO                0
 * Let lwip use linux standard errno
 */
#define LWIP_ERRNO_STDINCLUDE               1

// Control DBG messages
#define SOCKETS_DEBUG                       LWIP_DBG_ON
#define TCP_DEBUG                           LWIP_DBG_ON
//#define TCP_INPUT_DEBUG                     LWIP_DBG_ON
//#define TCP_OUTPUT_DEBUG                    LWIP_DBG_ON
//#define TCP_QLEN_DEBUG                      LWIP_DBG_ON
//#define ETHARP_DEBUG                        LWIP_DBG_ON
//#define PBUF_DEBUG                          LWIP_DBG_ON
//#define IP_DEBUG                            LWIP_DBG_ON
//#define TCPIP_DEBUG                         LWIP_DBG_ON
//#define DHCP_DEBUG                          LWIP_DBG_ON
//#define UDP_DEBUG                           LWIP_DBG_ON
//#define MDNS_DEBUG                          LWIP_DBG_ON
//#define ICMP_DEBUG                          LWIP_DBG_ON


#define LWIP_LINUX_PORT_NUM                     32
#define LWIP_LINUX_SERVER_START_PORT_NUM        6677
#define LWIP_LINUX_CLIENT_START_PORT_NUM        0xC000

/* NO_SYS cannot be 1 when socket or netconn is supported */
#define NO_SYS                                  0 /* multi threads */
#define SYS_LIGHTWEIGHT_PROT                    1 /* multi threads */
#define LWIP_ALLOW_MEM_FREE_FROM_OTHER_CONTEXT  1 /* multi threads */
#define LWIP_TCPIP_CORE_LOCKING                 1 /* multi threads */
#define LWIP_NETCONN                            1
#define LWIP_SOCKET                             1

/* how many connection requests will be accepted */
#define DEFAULT_ACCEPTMBOX_SIZE                 10
/* how many packets can be received without processing */
#define DEFAULT_TCP_RECVMBOX_SIZE               20

#define MEMP_NUM_SYS_TIMEOUT                    \
                        (LWIP_NUM_SYS_TIMEOUT_INTERNAL + 8)

/* to prevent redifinition of struc timeval */
#define LWIP_TIMEVAL_PRIVATE                    0
//#define LWIP_COMPAT_MUTEX                       1

/* Enable DHCP to test it, disable UDP checksum to easier inject packets */
#define LWIP_DHCP                               1
/* Don't check offered address is used */
#define DHCP_DOES_ARP_CHECK                     0
/* netdb.c */
#define LWIP_DNS                                1
/* LWIP_RAND */
#define LWIP_RAND() ((u32_t)rand())

/* Minimal changes to opt.h required for tcp unit tests: */
#define TCP_MSS                                 1460
#define MEM_SIZE                                16000
#define TCP_SND_QUEUELEN                        40
#define MEMP_NUM_TCP_SEG                        TCP_SND_QUEUELEN
#define TCP_SND_BUF                             (12 * TCP_MSS)
#define TCP_WND                                 (10 * TCP_MSS)
#define LWIP_WND_SCALE                          1
#define TCP_RCV_SCALE                           1
// DIEWELT
/* pbuf tests need ~200KByte */
//#define PBUF_POOL_SIZE                          400
/* pbuf tests need ~200KByte */
#define PBUF_POOL_SIZE                          16

#define LWIP_NETCONN_SEM_PER_THREAD             0
#define TCP_OVERSIZE                            1
#define TCP_OVERSIZE_DBGCHECK                   0
#define LWIP_NETIF_TX_SINGLE_PBUF               1

/* Enable IGMP and MDNS for MDNS tests */
#define LWIP_IGMP                               1
#define LWIP_MDNS_RESPONDER                     1
#define LWIP_NUM_NETIF_CLIENT_DATA      (LWIP_MDNS_RESPONDER)
//#define LWIP_NETIF_EXT_STATUS_CALLBACK          1
//#define MDNS_RESP_USENETIF_EXTCALLBACK          1

/* Minimal changes to opt.h required for etharp unit tests: */
#define ETHARP_SUPPORT_STATIC_ENTRIES           1

/* ---------- ARP options ---------- */
#define LWIP_ARP                                1
//#define ARP_TABLE_SIZE                        10
//#define ARP_QUEUEING                          1

// setsockopt(ctx->fd, SOL_SOCKET, SO_REUSEADDR,
#define SO_REUSE                                1

#endif /* LWIP_HDR_LWIPOPTS_H */
