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

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace cucascade::io::rest {

/// Operations for which the reader can preserve the semantics of the original request.
enum class redirect_operation : std::uint8_t { other, object_head, suffix_probe, ranged_get };

/// One-hop delegation. Origin and targets are host[:port] as spelled on the wire.
struct redirect_policy {
  bool enabled{false};
  std::string origin;
  std::vector<std::string> allowed_targets;
};

/// Facts about the completed exchange. Views are borrowed for the duration of the call.
struct redirect_response {
  redirect_operation operation{redirect_operation::other};
  std::string_view origin_authority;  ///< Actual request authority, including an explicit port.
  bool origin_tls{};
  bool already_followed{};
  unsigned status{};
  std::size_t location_count{};  ///< Count all Location fields in the final response head.
  std::string_view location;     ///< Entire field value, without surrounding HTTP whitespace.
};

/// Maximum accepted Location field value, in bytes. A longer value must never be truncated.
inline constexpr std::size_t max_redirect_location_size = 2048;

/// Check admission after a successful final response head. When building the HTTP request target,
/// use the Location's path verbatim, substituting "/" for an empty path. Append any query,
/// including its leading "?", byte for byte (e.g. "?part=1" becomes "/?part=1").
/// Transport, TLS verification and cancellation belong to the caller. This function does not
/// perform I/O or retain the response.
[[nodiscard]] bool allow_redirect(redirect_policy const& policy,
                                  redirect_response const& response) noexcept;

}  // namespace cucascade::io::rest
