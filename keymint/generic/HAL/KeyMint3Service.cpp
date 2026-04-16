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
 ** Copyright 2020-2026 NXP
 **
 *********************************************************************************/
#define LOG_TAG "javacard.strongbox-service"

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

#include "JavacardKeyMint3Device.h"
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
#include "km_common/MWVersionInfo.h"
#include "keymint_utils.h"

using aidl::android::hardware::security::keymint::JavacardKeyMint3Device;
using aidl::android::hardware::security::keymint::JavacardRemotelyProvisionedComponentDevice;
using aidl::android::hardware::security::sharedsecret::JavacardSharedSecret;
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
constexpr int kKeymintVersion = 300;
constexpr static std::string kModuleName = "KEYMINT";
// Ensures HAL and applet version consistency. This is used as P1 byte in the APDU header. This
// value is used by the applet to confirm that the KeyMint HAL is running a compatible version of
// Keymint. If the versions do not match, the command is not executed.
constexpr uint8_t kP1 = 0x60;

template <typename T, class... Args> std::shared_ptr<T> addService(Args&&... args) {
    std::shared_ptr<T> ser = ndk::SharedRefBase::make<T>(std::forward<Args>(args)...);
    auto instanceName = std::string(T::descriptor) + "/strongbox";
    LOG(INFO) << "adding javacard strongbox service instance: " << instanceName;
    binder_status_t status =
        AServiceManager_addService(ser->asBinder().get(), instanceName.c_str());
    CHECK(status == STATUS_OK);
    return ser;
}

std::shared_ptr<ITransport> getTransportInstance() {
#if defined OMAPI_TRANSPORT
    return OmapiTransport::make(gStrongBoxAppletAID);
#elif defined HAL_TO_HAL_TRANSPORT
    return std::make_shared<HalToHalTransport>(gStrongBoxAppletAID);
#else
    return std::make_shared<SocketTransport>(gStrongBoxAppletAID);
#endif
}

int main() {
    LOG(INFO) << "Starting javacard strongbox service";
    LOG(INFO) << nxp::keymint::getModuleMWVersion(kModuleName, std::to_string(kKeymintVersion));
    ABinderProcess_setThreadPoolMaxThreadCount(0);
    // Javacard Secure Element
    std::shared_ptr<JavacardSecureElement> card =
        std::make_shared<JavacardSecureElement>(kP1, getTransportInstance());
    std::shared_ptr<::keymint::javacard::JavacardKeyMintDevice> device =
        std::make_shared<::keymint::javacard::JavacardKeyMintDevice>(card, kKeymintVersion);
    // Add Keymint Service
    addService<JavacardKeyMint3Device>(card, device);
    // Add Shared Secret Service
    addService<JavacardSharedSecret>(card);
    // Add Remotely Provisioned Component Service
    addService<JavacardRemotelyProvisionedComponentDevice>(card);

    LOG(INFO) << "Joining thread pool";
    ABinderProcess_joinThreadPool();
    return EXIT_FAILURE;  // should not reach
}
