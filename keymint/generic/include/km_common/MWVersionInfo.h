/*
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
** http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
**
** Copyright 2026 NXP
**
*/
#ifndef __NXP_MW_VERSION__
#define __NXP_MW_VERSION__

#include <iomanip>
#include <sstream>
#include <string>
namespace nxp::keymint {
// Chip variants (true = supported, false = not supported)
constexpr bool NXP_EN_SN110U = true;
constexpr bool NXP_EN_SN100U = true;
constexpr bool NXP_EN_SN220U = true;
constexpr bool NXP_EN_PN557 = true;
constexpr bool NXP_EN_PN560 = true;
constexpr bool NXP_EN_SN300U = true;
constexpr bool NXP_EN_SN330U = true;

// Version constants
constexpr uint8_t NFC_NXP_MW_ANDROID_VER = 17U;
constexpr uint8_t NFC_NXP_MW_VERSION_MAJ = 0x06;
constexpr uint8_t NFC_NXP_MW_VERSION_MIN = 0x00;
constexpr uint8_t NFC_NXP_MW_CUSTOMER_ID = 0x00;
constexpr uint8_t NFC_NXP_MW_RC_VERSION = 0x00;

struct NxpChipVariant {
    const char* chip_name;
    uint8_t bit_pos;
    bool enabled;
};

constexpr std::size_t kNumOfChipVariants = 7;
static constexpr std::array<NxpChipVariant, kNumOfChipVariants> kAllChipVariants = {
    {{"PN557", 11, NXP_EN_PN557},
     {"SN100U", 13, NXP_EN_SN100U},
     {"SN110U", 14, NXP_EN_SN110U},
     {"SN220U", 15, NXP_EN_SN220U},
     {"PN560", 16, NXP_EN_PN560},
     {"SN300U", 17, NXP_EN_SN300U},
     {"SN330U", 18, NXP_EN_SN330U}}};

const std::string getMWVersion() {
    uint32_t supported_variants = 0;

    for (const auto& variant : kAllChipVariants) {
        if (variant.enabled) {
            supported_variants |= (1U << variant.bit_pos);
        }
    }

    std::ostringstream oss;
    oss << "MW-HAL Version: NFC_AR_" << std::hex << std::uppercase << std::setfill('0')
        << std::setw(2) << static_cast<int>(NFC_NXP_MW_CUSTOMER_ID) << '_' << std::setw(5)
        << supported_variants << '_' << std::dec << std::setw(2)
        << static_cast<int>(NFC_NXP_MW_ANDROID_VER) << '.' << std::hex << std::setw(2)
        << static_cast<int>(NFC_NXP_MW_VERSION_MAJ) << '.' << std::setw(2)
        << static_cast<int>(NFC_NXP_MW_VERSION_MIN);
    oss << "_TC5";
    return oss.str();
}

std::string getModuleMWVersion(const std::string& moduleName,
                               const std::string& moduleVersionNum = "") {
    std::string result = moduleName;

    if (!moduleVersionNum.empty()) {
        result += " " + moduleVersionNum;
    }
    result += " " + getMWVersion();

    return result;
}
}  // namespace nxp::keymint
#endif  //__NXP_MW_VERSION__
