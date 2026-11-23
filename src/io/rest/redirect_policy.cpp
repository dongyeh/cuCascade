/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "io/rest/http/rules.hpp"

#include <cucascade/io/rest/redirect_policy.hpp>

#include <arpa/inet.h>

#include <algorithm>
#include <charconv>

namespace cucascade::io::rest {
namespace {

char lower_ascii(char c) noexcept
{
  return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
}

bool same_authority(std::string_view a, std::string_view b) noexcept
{
  return std::equal(a.begin(), a.end(), b.begin(), b.end(), [](char x, char y) {
    return lower_ascii(x) == lower_ascii(y);
  });
}

bool alnum_ascii(char c) noexcept
{
  return (lower_ascii(c) >= 'a' && lower_ascii(c) <= 'z') || http::detail::is_digit(c);
}

// Accept DNS names, IPv4 addresses and bracketed IPv6 literals. Keep the authority spelling
// intact for the allowlist comparison (in particular, do not normalize an explicit port).
bool valid_authority(std::string_view authority) noexcept
{
  if (authority.starts_with('[')) {
    auto const end = authority.find(']');
    if (end == std::string_view::npos || end <= 1 || end > INET6_ADDRSTRLEN) { return false; }
    char host[INET6_ADDRSTRLEN]{};
    auto const literal = authority.substr(1, end - 1);
    if (literal.find('\0') != std::string_view::npos) { return false; }
    std::copy(literal.begin(), literal.end(), host);
    in6_addr addr{};
    if (inet_pton(AF_INET6, host, &addr) != 1) { return false; }
    authority.remove_prefix(end + 1);
  } else {
    auto const host = authority.substr(0, authority.find(':'));
    if (host.empty() || !std::all_of(host.begin(), host.end(), [](char c) {
          return alnum_ascii(c) || c == '.' || c == '-' || c == '_';
        })) {
      return false;
    }
    authority.remove_prefix(host.size());
  }
  if (authority.empty()) { return true; }
  if (authority.front() != ':') { return false; }
  authority.remove_prefix(1);
  unsigned port{};
  auto const end    = authority.data() + authority.size();
  auto const parsed = std::from_chars(authority.data(), end, port);
  return parsed.ec == std::errc{} && parsed.ptr == end && port > 0 && port <= 65535;
}

bool valid_path_query(std::string_view text) noexcept
{
  // RFC 3986 pchar, slash and question mark. Check escapes without decoding signed bytes.
  constexpr std::string_view punctuation{"-._~!$&'()*+,;=:@/?"};
  for (std::size_t i = 0; i < text.size(); ++i) {
    auto const c = text[i];
    if (c == '%' && i + 2 < text.size() && http::detail::unhex(text[i + 1]) >= 0 &&
        http::detail::unhex(text[i + 2]) >= 0) {
      i += 2;
    } else if (!alnum_ascii(c) && punctuation.find(c) == std::string_view::npos) {
      return false;
    }
  }
  return true;
}

}  // namespace

bool allow_redirect(redirect_policy const& policy, redirect_response const& response) noexcept
{
  if (!policy.enabled || response.status != 307 || response.already_followed ||
      response.location_count != 1 || response.location.size() > max_redirect_location_size ||
      policy.origin.empty() || !same_authority(policy.origin, response.origin_authority)) {
    return false;
  }
  switch (response.operation) {
    case redirect_operation::object_head:
    case redirect_operation::suffix_probe:
    case redirect_operation::ranged_get: break;
    default: return false;
  }

  auto location = response.location;
  if (http::detail::iequals_lower(location.substr(0, 8), "https://")) {
    location.remove_prefix(8);
  } else if (!response.origin_tls &&
             http::detail::iequals_lower(location.substr(0, 7), "http://")) {
    location.remove_prefix(7);
  } else {
    return false;
  }

  auto const authority = location.substr(0, location.find_first_of("/?"));
  if (!valid_authority(authority) || !valid_path_query(location.substr(authority.size()))) {
    return false;
  }
  return std::any_of(policy.allowed_targets.begin(),
                     policy.allowed_targets.end(),
                     [&](auto const& target) { return same_authority(authority, target); });
}

}  // namespace cucascade::io::rest
