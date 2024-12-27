/*
 * main.c
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
#include "lwip.h"

//#define  ECHO_SERVER              1
//#define  TCP_CLIENT               1
#define  SOCKET_ECHO_SERVER       1
#define  SSL_SERVER               1

int main(void)
{
    pthread_t thread;

    if(net_init(NULL) != ERR_OK)
    {
        printf("Failed to initialize netif!\n");
        goto _EXIT;
    }

    thread = start_netif();
    if (thread < 0)
    {
        printf("Failed to start netif!\n");
        goto _EXIT;
    }

#ifdef ECHO_SERVER
    if (create_echo_server() != ERR_OK)
    {
        printf("Failed to create echo server!\n");
        goto _EXIT;
    }
#endif

#ifdef TCP_CLIENT
    ip_addr_t ip_addr = { TCP_REMOTE_SERVER_ADDR };
    if (tcp_client(&ip_addr, TCP_REMOTE_SERVER_PORT) != ERR_OK)
    {
        printf("Failed to connect to server!\n");
        goto _EXIT;
    }
#endif

#ifdef SOCKET_ECHO_SERVER
    if (create_socket_echo_server() != ERR_OK)
    {
        printf("Failed to create socket echo server!\n");
        goto _EXIT;
    }
#endif

#ifdef SSL_SERVER
    if (create_ssl_server() != ERR_OK)
    {
        printf("Failed to create ssl server!\n");
        goto _EXIT;
    }
#endif

#if !defined(SSL_SERVER) && !defined(SOCKET_ECHO_SERVER) && !defined(ECHO_SERVER) && !defined(TCP_CLIENT)
#error at least one client shall be defined!!!!
#endif

    pthread_join(thread, NULL);

_EXIT:
    net_quit();

    return 1;
}
