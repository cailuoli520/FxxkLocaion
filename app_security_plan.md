# APP端安全加固方案 (V3)

## 1. 方案总览与核心思想

本方案为APP端构建一个“零信任”和“纵深防御”的安全架构。其核心思想是：APP不再信任其运行的任何环境，所有敏感操作和校验逻辑都必须经过多层防护和验证。客户端的核心功能将强依赖于一个由可信服务端签发的、动态的、有时效性的授权令牌，任何防御环节被突破都将导致授权失效。

- **关键逻辑下沉**: 核心的验签、解密和反破解逻辑从Java/Kotlin层下沉到C/C++ Native层，对抗静态逆向分析。
- **短期令牌刷新**: 采用短生命周期的`AccessToken`和长生命周期的`RefreshToken`机制，降低令牌泄露风险，并支持服务端远程吊销。
- **通信信道锁定**: 强制启用SSL证书绑定（SSL Pinning），彻底杜绝通过中间人代理抓包和篡改请求的可能。
- **本地存储加密**: 使用`EncryptedSharedPreferences`加密存储所有敏感令牌信息，防止在Root设备上被直接窃取。
- **运行时自我保护 (RASP)**: 在Native层实现反调试、反Hook检测，使动态分析和破解的难度大大增加。

---

## 2. 客户端详细实现步骤

### 2.1. 项目准备与依赖 (NDK & Crypto)

1.  在`app/build.gradle.kts`中配置NDK构建环境，并确保CMakeLists.txt配置正确。
2.  添加AndroidX安全库和OkHttp（或其他支持SSL Pinning的网络库）依赖：
    ```kotlin
    // 用于加密SharedPreferences
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    
    // 用于网络请求和SSL Pinning
    implementation("com.squareup.okhttp3:okhttp:4.10.0") 
    ```

### 2.2. Native层核心实现 (`src/main/cpp/security_core.cpp`)

这是防御体系的核心，所有敏感计算都在此进行。

1.  **JNI接口定义 (`security_bridge.h`)**:
    ```cpp
    #include <jni.h>

    extern "C" {
    // 校验令牌签名，解密Payload，并校验内部设备画像
    JNIEXPORT jbyteArray JNICALL
    Java_org_xiyu_fxxklocation_security_NativeBridge_verifyAndDecryptToken(
            JNIEnv *env, jobject thiz, jstring token, jstring signature, jstring device_id, jstring app_version, jstring apk_hash);

    // 执行运行时安全检查
    JNIEXPORT jboolean JNICALL
    Java_org_xiyu_fxxklocation_security_NativeBridge_raspCheck(JNIEnv *env, jobject thiz);

    // 从解密后的Payload中提取动态密钥，并用它解密出真正的参数
    JNIEXPORT jstring JNICALL
    Java_org_xiyu_fxxklocation_security_NativeBridge_getHookParameter(
            JNIEnv *env, jobject thiz, jbyteArray payload, jstring encrypted_param);
    }
    ```
2.  **C++实现**:
    - 使用OpenSSL等C++加密库，将**RSA公钥**硬编码在C++代码中，并进行混淆处理。
    - **`verifyAndDecryptToken`**: 实现完整的RSA验签和解密流程。解密后，必须再次比较传入的`device_id`, `app_version`, `apk_hash`与Payload中的内容是否完全一致。
    - **`raspCheck`**: 实现反调试（`ptrace`）、反Hook（扫描`/proc/self/maps`中的Frida/Xposed特征so库）。
    - **`getHookParameter`**: 接受已验证的Payload，从中提取`dynamic_key`，用该key解密传入的`encrypted_param`，返回最终可供Hook使用的明文参数。

### 2.3. Java/Kotlin层 (作为桥接层)

1.  **`NativeBridge.kt`**:
    ```kotlin
    object NativeBridge {
        init {
            System.loadLibrary("security_core")
        }
        external fun verifyAndDecryptToken(...): ByteArray?
        external fun raspCheck(): Boolean
        external fun getHookParameter(...): String?
    }
    ```
2.  **`ActivationManager.kt` (实现SSL Pinning)**:
    - 生成服务器证书的公钥哈希值。
    - 配置OkHttp客户端：
      ```kotlin
      val certificatePinner = CertificatePinner.Builder()
          .add("your-api-domain.com", "sha256/your_certificate_hash_base64")
          .build()
      
      val okHttpClient = OkHttpClient.Builder()
          .certificatePinner(certificatePinner)
          .build()
      ```
    - 所有激活、刷新的网络请求都必须使用此`okHttpClient`实例。

3.  **`AuthorizationState.kt` (双令牌管理 & 加密存储)**:
    - 初始化`EncryptedSharedPreferences`:
      ```kotlin
      val sharedPreferences = EncryptedSharedPreferences.create(
          context,
          "secret_prefs",
          MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
          EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
          EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
      )
      ```
    - **`getValidAccessTokenPayload()`**:
        1. 从加密存储中读取`AccessToken`。
        2. 调用`NativeBridge.verifyAndDecryptToken()`进行验证。
        3. 如果有效且未过期，返回解密后的Payload。
        4. 如果过期，读取`RefreshToken`，调用`NativeBridge`验证其有效性。
        5. `RefreshToken`有效，则调用`ActivationManager.refreshToken()`去服务端静默换取新的`AccessToken`。
        6. 成功换取后，加密存储新的`AccessToken`，并返回其Payload。
        7. 若所有路径都失败，则清除本地所有令牌并返回`null`。

### 2.4. 模块入口修改 (`ModuleMain.kt`)

```kotlin
// 在 handleLoadPackage 的最开始
fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
    // 1. Native层运行时安全自检
    if (NativeBridge.raspCheck()) {
        // 检测到攻击，可以执行退出、崩溃或功能瘫痪等操作
        return 
    }

    // 2. 获取已验证、解密的授权信息
    val tokenPayload = AuthorizationState.getValidAccessTokenPayload()
    if (tokenPayload == null) {
        // 未激活或授权失效，只加载UI相关的Hook让用户可以激活
        HookUIRelatedOnly(lpparam)
        return 
    }

    // 3. 从Native层获取真正可用的参数
    // "some_encrypted_string" 是一个在代码中硬编码的、被动态密钥加密的参数
    val realHookParam = NativeBridge.getHookParameter(tokenPayload, "some_encrypted_string")
    if (realHookParam == null) {
        // 动态密钥错误或解密失败
        return
    }

    // 4. 使用解密后的参数初始化核心Hook
    GnssHooks.init(realHookParam)
    // ... 其他Hooks
}
```

---

## 3. APP端防御策略总结

| 防御策略 | 攻击场景 | V3 解决方案 |
| :--- | :--- | :--- |
| **代码逆向** | 静态分析Java/Kotlin代码，寻找校验逻辑。 | **关键逻辑下沉到Native (C++)**，逆向成本指数级增加。配合高级代码混淆。 |
| **本地破解** | Root设备后，修改SharedPreferences中的`is_activated`标志。 | **加密SharedPreferences**使明文不可读。**令牌机制**取代简单标志，被篡改则验签失败。 |
| **动态调试/Hook** | 使用Frida/Xposed动态Hook校验函数，使其恒返回`true`。 | **Native层RASP**使用更底层的反调试/反Hook技术。**动态密钥强依赖**，即使Hook了校验函数，也拿不到正确密钥，核心功能依然瘫痪。 |
| **中间人攻击** | 使用Charles/Fiddler抓包，伪造服务端成功响应。 | **SSL Pinning**使客户端不信任任何非法的服务器证书，中间人无法解密HTTPS流量，抓包失败。 |
| **令牌泄露** | 即使攻击者通过某种方式获取了`AccessToken`。 | **短期令牌 (24h)**使其快速失效。**设备画像绑定**使其在其他设备上无效。 |
| **二次打包** | 破解者修改代码逻辑后重新打包APP分发。 | **APK签名Hash校验**，二次打包后签名变化，设备画像不匹配，激活/验证失败。 |
