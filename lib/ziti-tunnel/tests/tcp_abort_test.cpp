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

// An intercepted TCP connection, with a fake network interface under lwip and a fake ziti under the tunneler.
// The tests play the client by injecting the segments it would send, and read the segments lwip sends back.

#include <cstring>
#include <string>
#include <vector>

#include "catch2/catch.hpp"
#include "lwip/prot/tcp.h"
#include "lwip/tcp.h"
#include "ziti/ziti_tunnel.h"
#include "ziti_tunnel_priv.h"

namespace {
    const uint32_t CLIENT_IP = 0x64400101; // 100.64.1.1
    const uint32_t SERVER_IP = 0x0a630001; // 10.99.0.1
    const uint16_t SERVER_PORT = 9000;

    struct segment {
        uint8_t flags;
        uint32_t seq;
        uint32_t ack;
        size_t len; // payload
    };

    // the fake network interface
    std::vector<segment> sent;
    packet_cb inject_cb = nullptr;
    void *inject_netif = nullptr;

    // the fake ziti
    std::vector<io_ctx_t *> dialed;
    std::vector<struct write_ctx_s *> pending_writes; // what the client wrote, not acked yet
    int ziti_closes = 0;

    uint16_t checksum(const uint8_t *d, size_t n, uint32_t sum = 0) {
        for (; n > 1; d += 2, n -= 2) sum += (d[0] << 8) | d[1];
        if (n) sum += d[0] << 8;
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        return (uint16_t) ~sum;
    }

    void put16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }
    void put32(uint8_t *p, uint32_t v) { put16(p, v >> 16); put16(p + 2, v & 0xffff); }
    uint32_t get32(const uint8_t *p) { return ((uint32_t) p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]; }

    // an IPv4 TCP packet from the client to the intercepted address (or back, with from_client false)
    std::vector<uint8_t> packet(uint16_t client_port, uint32_t seq, uint32_t ack, uint8_t flags,
                                const std::string &payload = "", bool mss_option = false) {
        size_t tcp_len = 20 + (mss_option ? 4 : 0);
        std::vector<uint8_t> p(20 + tcp_len + payload.size());
        uint8_t *ip = p.data();
        uint8_t *tcp = ip + 20;
        ip[0] = 0x45;
        put16(ip + 2, (uint16_t) p.size());
        put16(ip + 6, 0x4000);
        ip[8] = 64;
        ip[9] = 6;
        put32(ip + 12, CLIENT_IP);
        put32(ip + 16, SERVER_IP);
        put16(ip + 10, checksum(ip, 20));

        put16(tcp, client_port);
        put16(tcp + 2, SERVER_PORT);
        put32(tcp + 4, seq);
        put32(tcp + 8, ack);
        tcp[12] = (uint8_t) ((tcp_len / 4) << 4);
        tcp[13] = flags;
        put16(tcp + 14, 0xffff);
        if (mss_option) {
            tcp[20] = 2;
            tcp[21] = 4;
            put16(tcp + 22, 1360);
        }
        memcpy(tcp + tcp_len, payload.data(), payload.size());

        uint8_t pseudo[12];
        put32(pseudo, CLIENT_IP);
        put32(pseudo + 4, SERVER_IP);
        pseudo[8] = 0;
        pseudo[9] = 6;
        put16(pseudo + 10, (uint16_t) (tcp_len + payload.size()));
        uint32_t sum = 0;
        for (int i = 0; i < 12; i += 2) sum += (pseudo[i] << 8) | pseudo[i + 1];
        put16(tcp + 16, checksum(tcp, tcp_len + payload.size(), sum));
        return p;
    }

    void inject(const std::vector<uint8_t> &p) {
        inject_cb((const char *) p.data(), (ssize_t) p.size(), inject_netif);
    }

    int fake_setup(netif_handle, uv_loop_t *, packet_cb cb, void *netif) {
        inject_cb = cb;
        inject_netif = netif;
        return 0;
    }

    ssize_t fake_write(netif_handle, const void *buf, size_t len) {
        const uint8_t *ip = (const uint8_t *) buf;
        const uint8_t *tcp = ip + (ip[0] & 0xf) * 4;
        size_t tcp_hlen = (tcp[12] >> 4) * 4;
        sent.push_back({tcp[13], get32(tcp + 4), get32(tcp + 8), len - (tcp - ip) - tcp_hlen});
        return (ssize_t) len;
    }

    int fake_add_route(netif_handle, const char *) { return 0; }

    void *fake_dial(const void *, io_ctx_t *io) {
        dialed.push_back(io);
        io->ziti_io = io; // anything not NULL
        return io;
    }

    ssize_t fake_write_ziti(const void *, void *write_ctx, const void *, size_t) {
        pending_writes.push_back((struct write_ctx_s *) write_ctx);
        return 0;
    }

    int fake_close(void *) {
        ziti_closes++;
        return 0;
    }

    int fake_close_write(void *) { return 0; }

    host_ctx_t *fake_host(void *, tunneler_context, const char *, cfg_type_e, const void *) { return nullptr; }

    tunneler_context tunneler() {
        static netif_driver_t netif = {};
        static tunneler_context tnlr = nullptr;
        if (tnlr == nullptr) {
            netif.setup = fake_setup;
            netif.write = fake_write;
            netif.add_route = fake_add_route;
            netif.mtu = 1400;
            static tunneler_sdk_options opts = {};
            opts.l3_netif_driver = &netif;
            opts.ziti_dial = fake_dial;
            opts.ziti_write = fake_write_ziti;
            opts.ziti_close = fake_close;
            opts.ziti_close_write = fake_close_write;
            opts.ziti_host = fake_host;
            // lwip is initialized once per process, and so is this
            tnlr = ziti_tunneler_init(&opts, uv_default_loop());

            intercept_ctx_t *intercept = intercept_ctx_new(tnlr, "abort-test", nullptr);
            intercept_ctx_add_protocol(intercept, "tcp");
            ziti_address za;
            REQUIRE(ziti_address_from_string(&za, "10.99.0.1"));
            intercept_ctx_add_address(intercept, &za);
            intercept_ctx_add_port_range(intercept, SERVER_PORT, SERVER_PORT);
            REQUIRE(ziti_tunneler_intercept(tnlr, intercept) == 0);
        }
        return tnlr;
    }

    // one intercepted connection. The ports are different for every one, lwip keeps the pcbs of the connections
    // that ended around for a while.
    struct client {
        uint16_t port;
        uint32_t seq = 1000;     // the next sequence number of the client
        uint32_t server_next = 0; // the next byte of the server the client has not seen
        size_t received = 0;     // data bytes of the server
        bool saw_fin = false, saw_rst = false;
        io_ctx_t *io = nullptr;

        explicit client(tunneler_context tnlr) {
            static uint16_t next_port = 40000;
            port = next_port++;
            sent.clear();
            dialed.clear();
            pending_writes.clear();
            ziti_closes = 0;

            inject(packet(port, seq, 0, TCP_SYN, "", true));
            REQUIRE(dialed.size() == 1);
            io = dialed[0];
            ziti_tunneler_dial_completed(io, true);
            REQUIRE(!sent.empty());
            REQUIRE((sent.back().flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK));
            server_next = sent.back().seq + 1;
            seq++;
            inject(packet(port, seq, server_next, TCP_ACK));
            sent.clear();
            (void) tnlr;
        }

        // the segments of the server since the last call, as the client reads them
        void read() {
            for (auto &s: sent) {
                if (s.flags & TCP_RST) saw_rst = true;
                if (s.len > 0 && s.seq == server_next) {
                    server_next += (uint32_t) s.len;
                    received += s.len;
                }
                if (s.flags & TCP_FIN) {
                    saw_fin = true;
                    server_next++;
                }
            }
            sent.clear();
        }

        // the client acks what it has read until the server has nothing more to send
        void ack_until_done(int max_rounds = 100) {
            read();
            for (int i = 0; i < max_rounds && !saw_rst; i++) {
                inject(packet(port, seq, server_next, TCP_ACK));
                size_t before = received;
                bool fin = saw_fin;
                read();
                if (received == before && saw_fin == fin) break;
            }
        }
    };

    size_t write_to_client(client &c, size_t len) {
        std::string data(len, 'x');
        ssize_t n = ziti_tunneler_write(c.io->tnlr_io, data.data(), data.size());
        REQUIRE(n > 0);
        return (size_t) n;
    }

    void finish(client &c) {
        // what the ziti connection's close callback does
        ziti_tunneler_close(c.io->tnlr_io);
        free(c.io);
    }
}

TEST_CASE("an abort resets the client after the data that was queued for it", "[tcp][abort]") {
    tunneler_context tnlr = tunneler();
    client c(tnlr);

    // more than lwip sends without being acked: part of it is in flight, part still queued
    size_t total = write_to_client(c, 20000);
    c.read();
    REQUIRE(c.received > 0);
    REQUIRE(c.received < total);
    REQUIRE(!c.saw_rst);

    ziti_tunneler_abort(c.io->tnlr_io);
    c.read();
    // not yet: the client has not got all of it
    CHECK(!c.saw_rst);

    c.ack_until_done();
    CHECK(c.received == total);
    CHECK(c.saw_rst);
    CHECK(!c.saw_fin);
    finish(c);
}

TEST_CASE("an abort with nothing queued resets the client at once", "[tcp][abort]") {
    tunneler_context tnlr = tunneler();
    client c(tnlr);

    size_t total = write_to_client(c, 100);
    c.read();
    // the client has it
    inject(packet(c.port, c.seq, c.server_next, TCP_ACK));
    ziti_tunneler_abort(c.io->tnlr_io);
    c.read();
    CHECK(total == 100);
    CHECK(c.saw_rst);
    finish(c);
}

TEST_CASE("a close does not reset the client", "[tcp][abort]") {
    tunneler_context tnlr = tunneler();
    client c(tnlr);

    size_t total = write_to_client(c, 20000);
    ziti_tunneler_close(c.io->tnlr_io);
    c.ack_until_done();
    CHECK(c.received == total);
    CHECK(c.saw_fin);
    CHECK(!c.saw_rst);
    free(c.io);
}

TEST_CASE("an ack of a client write after an abort does not touch the connection", "[tcp][abort]") {
    tunneler_context tnlr = tunneler();
    client c(tnlr);

    inject(packet(c.port, c.seq, c.server_next, TCP_ACK | TCP_PSH, "hello"));
    c.seq += 5;
    REQUIRE(pending_writes.size() == 1);
    struct write_ctx_s *write = pending_writes[0];
    struct tcp_pcb *pcb = c.io->tnlr_io->tcp;

    ziti_tunneler_abort(c.io->tnlr_io);
    c.read();
    REQUIRE(c.saw_rst);
    // the ziti connection closes, with the write still pending in it
    ziti_tunneler_close(c.io->tnlr_io);
    free(c.io);

    // ziti is done with the write now: the pcb is gone (back in the pool of lwip), and the ack leaves it alone
    u32_t rcv_wnd = pcb->rcv_wnd;
    sent.clear();
    ziti_tunneler_ack(write);
    CHECK(pcb->rcv_wnd == rcv_wnd);
    CHECK(sent.empty());
}

TEST_CASE("an ack of a client write after the client reset the connection", "[tcp][abort]") {
    tunneler_context tnlr = tunneler();
    client c(tnlr);

    inject(packet(c.port, c.seq, c.server_next, TCP_ACK | TCP_PSH, "hello"));
    c.seq += 5;
    REQUIRE(pending_writes.size() == 1);
    struct write_ctx_s *write = pending_writes[0];
    struct tcp_pcb *pcb = c.io->tnlr_io->tcp;

    // lwip frees the pcb and tells the tunneler, which closes ziti
    inject(packet(c.port, c.seq, c.server_next, TCP_RST | TCP_ACK));
    CHECK(ziti_closes == 1);
    ziti_tunneler_close(c.io->tnlr_io);
    free(c.io);

    u32_t rcv_wnd = pcb->rcv_wnd;
    sent.clear();
    ziti_tunneler_ack(write);
    CHECK(pcb->rcv_wnd == rcv_wnd);
    CHECK(sent.empty());
}

TEST_CASE("an ack of a client write before the connection is closed opens the window", "[tcp][abort]") {
    tunneler_context tnlr = tunneler();
    client c(tnlr);

    inject(packet(c.port, c.seq, c.server_next, TCP_ACK | TCP_PSH, "hello"));
    REQUIRE(pending_writes.size() == 1);
    CHECK(c.io->tnlr_io->pending_writes == 1);
    ziti_tunneler_ack(pending_writes[0]);
    CHECK(c.io->tnlr_io->pending_writes == 0);
    finish(c);
}
