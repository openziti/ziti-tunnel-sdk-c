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

#include "catch2/catch.hpp"
#include "../dns_host.h"

TEST_CASE("resolve", "[dns]") {
    dns_host_init();

    resolver_t resolver;
    res_ninit(&resolver);

    dns_message msg = {0};

    dns_question q;
    q.type = 15;
    q.name = strdup("yahoo.com");

    do_query(&q, &msg, &resolver);

    size_t jsonlen;
    auto json = dns_message_to_json(&msg, 0, &jsonlen);
    printf("%.*s\n\n", (int)jsonlen, json);

    res_nclose(&resolver);
    free(json);
    free_dns_message(&msg);
}


TEST_CASE("resolveSRV", "[dns]") {
    dns_host_init();

    resolver_t resolver;
    res_ninit(&resolver);

    dns_message msg = {0};

    dns_question q;
    q.type = 33;
    q.name = strdup("_imaps._tcp.gmail.com");

    do_query(&q, &msg, &resolver);

    CHECK(msg.status == 0);
    REQUIRE(msg.answer != nullptr);
    CHECK(msg.answer[0]->type == 33);
    CHECK(msg.answer[0]->port == 993);
    CHECK_THAT(msg.answer[0]->data, Catch::Contains("imap.gmail.com"));

    size_t jsonlen;
    auto json = dns_message_to_json(&msg, 0, &jsonlen);
    printf("%.*s\n\n", (int)jsonlen, json);

    res_nclose(&resolver);
    free(json);
    free_dns_message(&msg);
}

TEST_CASE("dns wire parse", "[dns]") {
    unsigned char b[] = {
  0x53, 0x6b, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x01, 0x05, 0x79, 0x61, 0x68,
  0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
  0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a,
  0x00, 0x08, 0x28, 0x27, 0x1d, 0x17, 0x27, 0x50,
  0xa0, 0x4e
};

    dns_message req = {0};
    CHECK(parse_dns_req(&req, b, sizeof(b)) == 0);

    CHECK(req.answer == nullptr);

    CHECK(req.question != nullptr);
    CHECK(req.question[0] != nullptr);
    CHECK(req.question[1] == nullptr);

    CHECK(req.question[0]->type == 1);
    CHECK_THAT(req.question[0]->name, Catch::Matches("yahoo.com"));

    free_dns_message(&req);
}

TEST_CASE("dns parse MX", "[dns]") {
    uint8_t b[] = {
  0xbd, 0x2d, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x01, 0x05, 0x79, 0x61, 0x68,
  0x6f, 0x6f, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
  0x0f, 0x00, 0x01, 0x00, 0x00, 0x29, 0x02, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

    dns_message req = {0};
    CHECK(parse_dns_req(&req, b, sizeof(b)) == 0);

    CHECK(req.answer == nullptr);

    CHECK(req.question != nullptr);
    CHECK(req.question[0] != nullptr);
    CHECK(req.question[1] == nullptr);

    CHECK(req.question[0]->type == 15);
    CHECK_THAT(req.question[0]->name, Catch::Matches("yahoo.com"));

    free_dns_message(&req);

}

#if !_WIN32
#include <vector>

// builds a DNS response for "a.test" that holds only an answer section
struct dns_resp_builder {
    std::vector<uint8_t> buf;

    dns_resp_builder(): buf({
        0x12, 0x34, 0x81, 0x80, // id, flags: response, no error
        0x00, 0x00, 0x00, 0x00, // qdcount, ancount
        0x00, 0x00, 0x00, 0x00, // nscount, arcount
    }) {}

    void rr(uint16_t type, const std::vector<uint8_t> &rdata) {
        const uint8_t fixed[] = {
            0x01, 'a', 0x04, 't', 'e', 's', 't', 0x00,
            (uint8_t)(type >> 8), (uint8_t)type,
            0x00, 0x01, // class IN
            0x00, 0x00, 0x00, 0x3c, // ttl
            (uint8_t)(rdata.size() >> 8), (uint8_t)rdata.size(),
        };
        buf.insert(buf.end(), fixed, fixed + sizeof(fixed));
        buf.insert(buf.end(), rdata.begin(), rdata.end());
        buf[7]++; // ancount
    }

    void format(dns_message *resp) {
        // exact size heap copy lets memory checkers see reads past the end of the message
        std::vector<uint8_t> msg(buf);
        msg.shrink_to_fit();
        ns_msg handle;
        REQUIRE(ns_initparse(msg.data(), (int)msg.size(), &handle) == 0);
        format_dns_answers(&handle, resp);
    }
};

static int count_answers(const dns_message *msg) {
    int count = 0;
    while (msg->answer != nullptr && msg->answer[count] != nullptr) count++;
    return count;
}

TEST_CASE("format dns answers", "[dns]") {
    dns_host_init();

    dns_resp_builder b;
    b.rr(ns_t_txt, {0x05, 'h', 'e', 'l', 'l', 'o'});
    b.rr(ns_t_srv, {0x00, 0x0a, 0x00, 0x14, 0x03, 0xe1, 0x03, 's', 'r', 'v', 0x04, 't', 'e', 's', 't', 0x00});
    b.rr(ns_t_mx, {0x00, 0x05, 0x02, 'm', 'x', 0x04, 't', 'e', 's', 't', 0x00});
    b.rr(ns_t_txt, {0x00});

    dns_message msg = {0};
    b.format(&msg);

    REQUIRE(count_answers(&msg) == 4);

    CHECK(msg.answer[0]->type == ns_t_txt);
    CHECK(msg.answer[0]->ttl == 60);
    CHECK_THAT(msg.answer[0]->data, Catch::Matches("hello"));

    CHECK(msg.answer[1]->type == ns_t_srv);
    CHECK(msg.answer[1]->priority == 10);
    CHECK(msg.answer[1]->weight == 20);
    CHECK(msg.answer[1]->port == 993);
    CHECK_THAT(msg.answer[1]->data, Catch::Matches("srv.test"));

    CHECK(msg.answer[2]->type == ns_t_mx);
    CHECK(msg.answer[2]->priority == 5);
    CHECK_THAT(msg.answer[2]->data, Catch::Matches("mx.test"));

    CHECK(msg.answer[3]->type == ns_t_txt);
    CHECK_THAT(msg.answer[3]->data, Catch::Matches(""));

    free_dns_message(&msg);
}

TEST_CASE("format dns answers drops TXT without data", "[dns]") {
    dns_host_init();

    dns_resp_builder b;
    b.rr(ns_t_txt, {});

    dns_message msg = {0};
    b.format(&msg);

    CHECK(count_answers(&msg) == 0);

    free_dns_message(&msg);
}

TEST_CASE("format dns answers drops short SRV and MX", "[dns]") {
    dns_host_init();

    auto rdata = GENERATE(
            std::make_pair((int)ns_t_srv, std::vector<uint8_t>{}),
            std::make_pair((int)ns_t_srv, std::vector<uint8_t>{0x00, 0x0a}),
            // no target
            std::make_pair((int)ns_t_srv, std::vector<uint8_t>{0x00, 0x0a, 0x00, 0x14, 0x03, 0xe1}),
            // target runs past the end of the message
            std::make_pair((int)ns_t_srv, std::vector<uint8_t>{0x00, 0x0a, 0x00, 0x14, 0x03, 0xe1, 0x03, 's'}),
            std::make_pair((int)ns_t_mx, std::vector<uint8_t>{}),
            std::make_pair((int)ns_t_mx, std::vector<uint8_t>{0x00}),
            // no exchange
            std::make_pair((int)ns_t_mx, std::vector<uint8_t>{0x00, 0x05}),
            // exchange runs past the end of the message
            std::make_pair((int)ns_t_mx, std::vector<uint8_t>{0x00, 0x05, 0x02, 'm'})
    );

    dns_resp_builder b;
    b.rr((uint16_t)rdata.first, rdata.second);

    dns_message msg = {0};
    b.format(&msg);

    CHECK(count_answers(&msg) == 0);

    free_dns_message(&msg);
}

TEST_CASE("format dns answers drops name that leaves the record data", "[dns]") {
    dns_host_init();

    dns_resp_builder b;
    // the target claims more octets than the record holds and continues into the next record
    b.rr(ns_t_srv, {0x00, 0x0a, 0x00, 0x14, 0x03, 0xe1, 0x08, 's'});
    b.rr(ns_t_txt, {0x05, 'h', 'e', 'l', 'l', 'o'});

    dns_message msg = {0};
    b.format(&msg);

    REQUIRE(count_answers(&msg) == 1);
    CHECK(msg.answer[0]->type == ns_t_txt);

    free_dns_message(&msg);
}
#endif
