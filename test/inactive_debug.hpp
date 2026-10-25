// SPDX-FileCopyrightText: 2026 Huang Rui <vowstar@gmail.com>
// SPDX-License-Identifier: MIT
#pragma once
#include <type_traits>
#include <utility>

template<class T, class = void> struct HasDmi : std::false_type {};
template<class T> struct HasDmi<T, std::void_t<decltype(std::declval<T>().dmi_request_valid)>>
    : std::true_type {};

template<class T> void inactiveDebug(T &dut) {
    if constexpr (HasDmi<T>::value) {
        dut.dmi_request_valid = 0;
        dut.dmi_request_bits_address = 0;
        dut.dmi_request_bits_data = 0;
        dut.dmi_request_bits_op = 0;
        dut.dmi_response_ready = 1;
    }
}
