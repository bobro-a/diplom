cmake_minimum_required(VERSION 3.10)
project(connman_dhcp C)

set(CMAKE_C_STANDARD 99)

# Указать путь к исходникам DHCP-модуля
set(SOURCES

        src/connman.h
        src/6to4.c
        src/agent-connman.c
        src/agent.c
        src/backtrace.c
        src/bridge.c
        src/clock.c
        src/config.c
        src/connection.c
        src/connmand-wait-online.c
        src/counter.c
        src/dbus.c
        src/detect.c
        src/device.c
        src/dhcp.c
        src/dhcpv6.c
        src/dnsproxy.c
        src/eduroam.config
        src/error.c
        src/firewall.c
        src/genbuiltin
        src/inet.c
        src/inotify.c
        src/ipaddress.c
        src/ipconfig.c
        src/ippool.c
        src/iptables.c
        src/ipv6pd.c
        src/log.c
        src/machine.c
        src/main.c
        src/main.conf
        src/manager.c
        src/nat.c
        src/net.connman.service.in
        src/network.c
        src/notifier.c
        src/ntp.c
        src/peer.c
        src/peer_service.c
        src/plugin.c
        src/provider.c
        src/proxy.c
        src/resolver.c
        src/rfkill.c
        src/rtnl.c
        src/service.c
        src/session.c
        src/shared
        src/stats.c
        src/storage.c
        src/task.c
        src/technology.c
        src/tethering.c
        src/timeserver.c
        src/timezone.c
        src/util.c
        src/utsname.c
        src/wispr.c
        src/wpad.c
        gdhcp/client.c
        gdhcp/common.c
        gdhcp/common.h
        gdhcp/gdhcp.h
        gdhcp/ipv4ll.c
        gdhcp/ipv4ll.h
        gdhcp/server.c
        gdhcp/unaligned.h

        # Добавьте сюда другие необходимые исходники, связанные с DHCP
)

# Указать папки с заголовочными файлами
include_directories(
        src
        include
        gdhcp
        wifi
        # Укажите ещё пути, если нужны
)

# Добавляем внешний GDHCP, если используется как библиотека
# Если GDHCP - часть исходников, добавьте её в SOURCES
# find_library(GDHCP_LIB gdhcp) # если установлена библиотека
# target_link_libraries(connman_dhcp PRIVATE ${GDHCP_LIB})

# Создаем библиотеку для DHCP-модуля
add_library(connman_dhcp STATIC ${SOURCES})

target_include_directories(connman_dhcp PRIVATE ${GLIB_INCLUDE_DIRS})
target_link_libraries(connman_dhcp PRIVATE ${GLIB_LIBRARIES})

# Если нужен исполняемый файл отдельно
# add_executable(dhcp_test src/dhcp_main.c)
# target_link_libraries(dhcp_test connman_dhcp)

