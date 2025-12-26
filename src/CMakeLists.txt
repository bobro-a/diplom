cmake_minimum_required(VERSION 3.16)
project(dhcp_wrapper C)

set(CMAKE_C_STANDARD 11)

# Найти pkg-config
find_package(PkgConfig REQUIRED)

# Найти необходимые библиотеки
pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(GLIB REQUIRED glib-2.0)

# Создать исполняемый файл
add_executable(dhcp_wrapper main.c connman-1.32/gdhcp/client.c
        connman-1.32/gdhcp/server.c
        connman-1.32/gdhcp/common.h
        connman-1.32/gdhcp/common.c
        connman-1.32/src/dnsproxy.c
        connman-1.32/src/tethering.c
        connman-1.32/src/peer.c)

# Подключить заголовочные файлы
target_include_directories(dhcp_wrapper PRIVATE
        ${PCAP_INCLUDE_DIRS}
        ${GLIB_INCLUDE_DIRS}
)

# Линковка библиотек
target_link_libraries(dhcp_wrapper PRIVATE
        ${PCAP_LIBRARIES}
        ${GLIB_LIBRARIES}
)

# Флаги компиляции
target_compile_options(dhcp_wrapper PRIVATE ${PCAP_CFLAGS_OTHER} ${GLIB_CFLAGS_OTHER})

# Для Linux добавить pthread если нужно
find_package(Threads REQUIRED)
target_link_libraries(dhcp_wrapper PRIVATE Threads::Threads)
