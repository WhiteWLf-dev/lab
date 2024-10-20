cmake_minimum_required(VERSION 3.10)

project(DESExample C)

set(CMAKE_C_STANDARD 11)

# Если указан путь к статической библиотеке, то используем его
if(DEFINED OPENSSL_ROOT_DIR)
    # Указываем путь к статической библиотеке
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    find_package(OpenSSL REQUIRED
        HINTS ${OPENSSL_ROOT_DIR}
        PATHS ${OPENSSL_ROOT_DIR}
    )
else()
    # Иначе ищем динамическую библиотеку как обычно
    find_package(OpenSSL REQUIRED)
endif()

# Добавляем исполняемый файл
add_executable(des main.c)

# Линкуем с OpenSSL
target_link_libraries(des OpenSSL::SSL OpenSSL::Crypto)
