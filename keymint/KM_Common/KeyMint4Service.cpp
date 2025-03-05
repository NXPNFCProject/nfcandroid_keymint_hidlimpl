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
 **
 ** The original Work has been changed by NXP.
 **
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
 ** Copyright 2020-2025 NXP
 **
 *********************************************************************************/
#include <aidl/android/hardware/security/keymint/SecurityLevel.h>

#define LOG_TAG "javacard.strongbox-service"
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <keymaster/km_version.h>

#include "JavacardKeyMint4Device.h"
#include "JavacardRemotelyProvisionedComponentDevice.h"
#include "JavacardSecureElement.h"
#include "JavacardSharedSecret.h"
#if defined OMAPI_TRANSPORT
#include <OmapiTransport.h>
#elif defined HAL_TO_HAL_TRANSPORT
#include <HalToHalTransport.h>
#else
#include <SocketTransport.h>
#endif
#include "keymint_utils.h"
#include <stdint.h>
#include <cstdio>

#define NXP_EN_SN110U 1
#define NXP_EN_SN100U 1
#define NXP_EN_SN220U 1
#define NXP_EN_PN557 1
#define NXP_EN_PN560 1
#define NXP_EN_SN300U 1
#define NXP_EN_SN330U 1
#define NFC_NXP_MW_ANDROID_VER (16U)  /* Android version used by NFC MW */
#define NFC_NXP_MW_VERSION_MAJ (0x04) /* MW Major Version */
#define NFC_NXP_MW_VERSION_MIN (0x00) /* MW Minor Version */
#define NFC_NXP_MW_CUSTOMER_ID (0x00) /* MW Customer Id */
#define NFC_NXP_MW_RC_VERSION (0x00)  /* MW RC Version */

using aidl::android::hardware::security::keymint::JavacardKeyMint4Device;
using aidl::android::hardware::security::keymint::JavacardRemotelyProvisionedComponentDevice;
using aidl::android::hardware::security::keymint::SecurityLevel;
using aidl::android::hardware::security::sharedsecret::JavacardSharedSecret;
using keymaster::KmVersion;
using keymint::javacard::getOsPatchlevel;
using keymint::javacard::getOsVersion;
using keymint::javacard::getVendorPatchlevel;
using keymint::javacard::ITransport;
using keymint::javacard::JavacardSecureElement;
#if defined OMAPI_TRANSPORT
using keymint::javacard::OmapiTransport;
#elif defined HAL_TO_HAL_TRANSPORT
using keymint::javacard::HalToHalTransport;
#else
using keymint::javacard::SocketTransport;
#endif

const std::vector<uint8_t> gStrongBoxAppletAID = {0xA0, 0x00, 0x00, 0x00, 0x62};

template <typename T, class... Args> std::shared_ptr<T> addService(Args&&... args) {
    std::shared_ptr<T> ser = ndk::SharedRefBase::make<T>(std::forward<Args>(args)...);
    auto instanceName = std::string(T::descriptor) + "/strongbox";
    LOG(INFO) << "adding javacard strongbox service instance: " << instanceName;
    binder_status_t status =
        AServiceManager_addService(ser->asBinder().get(), instanceName.c_str());
    CHECK(status == STATUS_OK);
    return ser;
}

static void printKeyMint4Version() {
  uint32_t validation = (NXP_EN_SN100U << 13);
  validation |= (NXP_EN_SN110U << 14);
  validation |= (NXP_EN_SN220U << 15);
  validation |= (NXP_EN_PN560 << 16);
  validation |= (NXP_EN_SN300U << 17);
  validation |= (NXP_EN_SN330U << 18);
  validation |= (NXP_EN_PN557 << 11);

  char version[60];  // Buffer to store formatted string
  sprintf(version, "KEY MINT 4 Version: NFC_AR_%02X_%05X_%02d.%02X.%02X",
          NFC_NXP_MW_CUSTOMER_ID, validation, NFC_NXP_MW_ANDROID_VER,
          NFC_NXP_MW_VERSION_MAJ, NFC_NXP_MW_VERSION_MIN);
  LOG(INFO) << version;
}

int main() {
    LOG(INFO) << "Starting javacard strongbox service";
    printKeyMint4Version();
    ABinderProcess_setThreadPoolMaxThreadCount(0);
    // Javacard Secure Element
#if defined OMAPI_TRANSPORT
    std::shared_ptr<JavacardSecureElement> card =
        std::make_shared<JavacardSecureElement>(KmVersion::KEYMINT_4,
            OmapiTransport::make(gStrongBoxAppletAID));
#elif defined HAL_TO_HAL_TRANSPORT
    std::shared_ptr<JavacardSecureElement> card =
        std::make_shared<JavacardSecureElement>(KmVersion::KEYMINT_4,
            std::make_shared<HalToHalTransport>(gStrongBoxAppletAID));
#else
    std::shared_ptr<JavacardSecureElement> card =
        std::make_shared<JavacardSecureElement>(KmVersion::KEYMINT_4,
            std::make_shared<SocketTransport>(gStrongBoxAppletAID));
#endif
    std::shared_ptr<::keymint::javacard::JavacardKeyMintDevice> device =
        std::make_shared<::keymint::javacard::JavacardKeyMintDevice>(card);
    // Add Keymint Service
    addService<JavacardKeyMint4Device>(card, device);
    // Add Shared Secret Service
    addService<JavacardSharedSecret>(card);
    // Add Remotely Provisioned Component Service
    addService<JavacardRemotelyProvisionedComponentDevice>(card);

    LOG(INFO) << "Joining thread pool";
    ABinderProcess_joinThreadPool();
    return EXIT_FAILURE;  // should not reach
}
