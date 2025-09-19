/*
 * Copyright 2020, The Android Open Source Project
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
 *  Copyright 2025 NXP
 *
 ******************************************************************************/

#pragma once

#include <aidl/android/hardware/security/keymint/BnKeyMintDevice.h>
#include <aidl/android/hardware/security/keymint/HardwareAuthToken.h>

#include <KeyMintUtils.h>

#include "JavacardKeyMintDevice.h"

namespace aidl::android::hardware::security::keymint {
using cppbor::Item;
using ::keymint::javacard::JavacardSecureElement;
using ndk::ScopedAStatus;
using secureclock::TimeStampToken;
using std::array;
using std::optional;
using std::shared_ptr;
using std::vector;

class JavacardKeyMint3Device : public BnKeyMintDevice {
  public:
    explicit JavacardKeyMint3Device(shared_ptr<JavacardSecureElement> card,
                                    shared_ptr<::keymint::javacard::JavacardKeyMintDevice> device)
        : device_(device) {}
    virtual ~JavacardKeyMint3Device() {}
    binder_status_t dump(int fd, const char** args, uint32_t num_args) {
        return device_->dump(fd, args, num_args);
    }

    ScopedAStatus getHardwareInfo(KeyMintHardwareInfo* info) {
        return device_->getHardwareInfo(info);
    }

    ScopedAStatus generateKey(const vector<KeyParameter>& keyParams,
                              const optional<AttestationKey>& attestationKey,
                              KeyCreationResult* creationResult) {
        return device_->generateKey(keyParams, attestationKey, creationResult);
    }

    ScopedAStatus addRngEntropy(const vector<uint8_t>& data) {
        return device_->addRngEntropy(data);
    }

    ScopedAStatus importKey(const vector<KeyParameter>& keyParams, KeyFormat keyFormat,
                            const vector<uint8_t>& keyData,
                            const optional<AttestationKey>& attestationKey,
                            KeyCreationResult* creationResult) {
        return device_->importKey(keyParams, keyFormat, keyData, attestationKey, creationResult);
    }

    ScopedAStatus importWrappedKey(const vector<uint8_t>& wrappedKeyData,
                                   const vector<uint8_t>& wrappingKeyBlob,
                                   const vector<uint8_t>& maskingKey,
                                   const vector<KeyParameter>& unwrappingParams,
                                   int64_t passwordSid, int64_t biometricSid,
                                   KeyCreationResult* creationResult) {
        return device_->importWrappedKey(wrappedKeyData, wrappingKeyBlob, maskingKey,
                                         unwrappingParams, passwordSid, biometricSid,
                                         creationResult);
    }

    ScopedAStatus upgradeKey(const vector<uint8_t>& keyBlobToUpgrade,
                             const vector<KeyParameter>& upgradeParams, vector<uint8_t>* keyBlob) {
        return device_->upgradeKey(keyBlobToUpgrade, upgradeParams, keyBlob);
    }

    ScopedAStatus deleteKey(const vector<uint8_t>& keyBlob) { return device_->deleteKey(keyBlob); }

    ScopedAStatus deleteAllKeys() { return device_->deleteAllKeys(); }

    ScopedAStatus destroyAttestationIds() { return device_->destroyAttestationIds(); }

    ScopedAStatus begin(KeyPurpose purpose, const std::vector<uint8_t>& keyBlob,
                        const std::vector<KeyParameter>& params,
                        const std::optional<HardwareAuthToken>& authToken, BeginResult* result) {
        return device_->begin(purpose, keyBlob, params, authToken, result);
    }

    ScopedAStatus deviceLocked(bool passwordOnly,
                               const std::optional<TimeStampToken>& timestampToken) {
        return device_->deviceLocked(passwordOnly, timestampToken);
    }

    ScopedAStatus earlyBootEnded() { return device_->earlyBootEnded(); }

    ScopedAStatus getKeyCharacteristics(const std::vector<uint8_t>& keyBlob,
                                        const std::vector<uint8_t>& appId,
                                        const std::vector<uint8_t>& appData,
                                        std::vector<KeyCharacteristics>* result) {
        return device_->getKeyCharacteristics(keyBlob, appId, appData, result);
    }

    ScopedAStatus convertStorageKeyToEphemeral(const std::vector<uint8_t>& /* storageKeyBlob */,
                                               std::vector<uint8_t>* /* ephemeralKeyBlob */) {
        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
    }

    ScopedAStatus getRootOfTrustChallenge(array<uint8_t, 16>* challenge) {
        return device_->getRootOfTrustChallenge(challenge);
    }

    ScopedAStatus getRootOfTrust(const array<uint8_t, 16>& /*challenge*/,
                                 vector<uint8_t>* /*rootOfTrust*/) {
        return km_utils::kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
    }

    ScopedAStatus sendRootOfTrust(const vector<uint8_t>& rootOfTrust) {
        return device_->sendRootOfTrust(rootOfTrust);
    }

  private:
    shared_ptr<::keymint::javacard::JavacardKeyMintDevice> device_;
};

}  // namespace aidl::android::hardware::security::keymint
