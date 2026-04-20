/*
 * Copyright 2025, The Android Open Source Project
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
/******************************************************************************
 *
 *  The original Work has been changed by NXP.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  Copyright 2025-2026 NXP
 *
 ******************************************************************************/
#define LOG_TAG "javacard.keymint.device.strongbox-impl"

#include "JavacardKeyMint4Device.h"

#include <algorithm>
#include <set>

namespace aidl::android::hardware::security::keymint {

const std::set<Tag> kAllowedAdditionalAttestationTags = {
    Tag::MODULE_HASH,
};

ScopedAStatus
JavacardKeyMint4Device::setAdditionalAttestationInfo(const vector<KeyParameter>& keyParams) {
    // Remove non additional attestation tags
    std::vector<KeyParameter> filtered;
    std::remove_copy_if(keyParams.begin(), keyParams.end(), std::back_inserter(filtered),
                        [](const auto& entry) -> bool {
                            return std::find(kAllowedAdditionalAttestationTags.begin(),
                                             kAllowedAdditionalAttestationTags.end(),
                                             entry.tag) == kAllowedAdditionalAttestationTags.end();
                        });
    return device_->setAdditionalAttestationInfo(filtered);
}

}  // namespace aidl::android::hardware::security::keymint
