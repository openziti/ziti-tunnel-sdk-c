/*
 Copyright NetFoundry Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

// app-info.c is compiled into this target with INSTALL_REG_ROOT/INSTALL_REG_KEY aimed at the key
// below, so every case writes real registry data under HKEY_CURRENT_USER: no elevation, and the
// installation key the production build reads is never touched.

// pulls in winsock2.h ahead of windows.h, and declares installed_app_version() with C linkage
#include "windows/windows-service.h"

#include <cstring>
#include <string>

#include "catch2/catch.hpp"

// Must match INSTALL_REG_KEY in this target's compile definitions.
#define TEST_REG_KEY "SOFTWARE\\ziti-edge-tunnel-test\\app-info"
#define TEST_REG_ROOT_KEY "SOFTWARE\\ziti-edge-tunnel-test"

namespace {

    void clear_key() {
        RegDeleteTreeA(HKEY_CURRENT_USER, TEST_REG_ROOT_KEY);
    }

    void create_key() {
        HKEY key;
        REQUIRE(RegCreateKeyExA(HKEY_CURRENT_USER, TEST_REG_KEY, 0, nullptr, 0,
                                KEY_WRITE, nullptr, &key, nullptr) == ERROR_SUCCESS);
        RegCloseKey(key);
    }

    // explicit type and byte count, so a case can store what no well-behaved writer produces: an
    // embedded NUL, or no terminator at all
    void set_version_raw(DWORD type, const void *data, DWORD bytes) {
        create_key();
        HKEY key;
        REQUIRE(RegOpenKeyExA(HKEY_CURRENT_USER, TEST_REG_KEY, 0, KEY_WRITE, &key) == ERROR_SUCCESS);
        REQUIRE(RegSetValueExA(key, "Version", 0, type, (const BYTE *) data, bytes) == ERROR_SUCCESS);
        RegCloseKey(key);
    }

    // a normal REG_SZ: the terminating NUL is part of the stored bytes
    void set_version(const std::string &value) {
        set_version_raw(REG_SZ, value.c_str(), (DWORD) value.size() + 1);
    }

    struct RegistryFixture {
        RegistryFixture() { clear_key(); }
        ~RegistryFixture() { clear_key(); }
    };

}

TEST_CASE_METHOD(RegistryFixture, "reports the installed version", "[app_info]") {
    set_version("2.11.4.0");
    REQUIRE(std::string(installed_app_version()) == "2.11.4.0");
}

TEST_CASE_METHOD(RegistryFixture, "reports unknown when the key is absent", "[app_info]") {
    REQUIRE(std::string(installed_app_version()) == APP_VERSION_UNKNOWN);
}

TEST_CASE_METHOD(RegistryFixture, "reports unknown when the key holds no Version", "[app_info]") {
    create_key();
    REQUIRE(std::string(installed_app_version()) == APP_VERSION_UNKNOWN);
}

TEST_CASE_METHOD(RegistryFixture, "reports unknown for an empty Version", "[app_info]") {
    set_version("");
    REQUIRE(std::string(installed_app_version()) == APP_VERSION_UNKNOWN);
}

TEST_CASE_METHOD(RegistryFixture, "reports unknown for a whitespace-only Version", "[app_info]") {
    set_version(" \t\r\n ");
    REQUIRE(std::string(installed_app_version()) == APP_VERSION_UNKNOWN);
}

TEST_CASE_METHOD(RegistryFixture, "trims whitespace around the version", "[app_info]") {
    set_version("  2.11.4.0\r\n");
    REQUIRE(std::string(installed_app_version()) == "2.11.4.0");
}

TEST_CASE_METHOD(RegistryFixture, "reports unknown for a non-string Version", "[app_info]") {
    SECTION("REG_DWORD") {
        DWORD numeric = 21140;
        set_version_raw(REG_DWORD, &numeric, sizeof(numeric));
    }
    SECTION("REG_EXPAND_SZ") {
        const char *expand = "%PROCESSOR_LEVEL%";
        set_version_raw(REG_EXPAND_SZ, expand, (DWORD) strlen(expand) + 1);
    }
    SECTION("REG_MULTI_SZ") {
        const char multi[] = "2.11.4.0\0009.9.9\000";
        set_version_raw(REG_MULTI_SZ, multi, (DWORD) sizeof(multi));
    }
    SECTION("REG_BINARY") {
        const unsigned char bytes[] = {0x02, 0x0b, 0x04, 0x00};
        set_version_raw(REG_BINARY, bytes, (DWORD) sizeof(bytes));
    }
    REQUIRE(std::string(installed_app_version()) == APP_VERSION_UNKNOWN);
}

TEST_CASE_METHOD(RegistryFixture, "reports unknown for an overlong version", "[app_info]") {
    set_version(std::string(300, '9'));
    REQUIRE(std::string(installed_app_version()) == APP_VERSION_UNKNOWN);
}

TEST_CASE_METHOD(RegistryFixture, "accepts a version at the length limit", "[app_info]") {
    const std::string at_limit(63, '7');
    set_version(at_limit);
    REQUIRE(std::string(installed_app_version()) == at_limit);
}

TEST_CASE_METHOD(RegistryFixture, "reports unknown one past the length limit", "[app_info]") {
    set_version(std::string(64, '7'));
    REQUIRE(std::string(installed_app_version()) == APP_VERSION_UNKNOWN);
}

// read as a C string this reports "1.2.3", which looks real and is not the installed version
TEST_CASE_METHOD(RegistryFixture, "reports unknown for a Version with an embedded NUL", "[app_info]") {
    const char embedded[] = "1.2.3\0bad";
    set_version_raw(REG_SZ, embedded, (DWORD) sizeof(embedded));
    REQUIRE(std::string(installed_app_version()) == APP_VERSION_UNKNOWN);
}

// storing a string without its terminator is well-formed, and the reader supplies one
TEST_CASE_METHOD(RegistryFixture, "accepts a Version with no terminator", "[app_info]") {
    const char unterminated[] = {'2', '.', '1', '1', '.', '4', '.', '0'};
    set_version_raw(REG_SZ, unterminated, (DWORD) sizeof(unterminated));
    REQUIRE(std::string(installed_app_version()) == "2.11.4.0");
}
