package org.xiyu.fxxklocation

import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge

@Volatile
internal var selinuxPolicyPatched = false

/**
 * Bypass SELinux for service_fl_ml registration.
 *
 * ServiceManager.addService() SELinux check happens in the native
 * servicemanager daemon (not Java) → cannot be hooked by Xposed.
 *
 * Solution: Hook ServiceManager.getService/checkService in system_server
 * to intercept queries for "service_fl_ml" / "service_fl_xp" and return
 * our binder directly, bypassing the native servicemanager entirely.
 * Also hook addService to suppress SecurityException for our services.
 *
 * For FL app process: use su setenforce 0 as fallback.
 */
internal fun applySELinuxPolicy(): Boolean {
    if (selinuxPolicyPatched) return true
    synchronized(ModuleMain::class.java) {
        if (selinuxPolicyPatched) return true

        // Strategy 1: su setenforce 0 (works from any process with root)
        try {
            val p = Runtime.getRuntime().exec(arrayOf("su", "-c", "setenforce 0"))
            val exit = p.waitFor()
            if (exit == 0) {
                selinuxPolicyPatched = true
                log("[SEPOL] SELinux set to Permissive via su")
                return true
            }
            log("[SEPOL] su setenforce exit=$exit")
        } catch (e: Throwable) {
            log("[SEPOL] su setenforce failed: $e")
        }

        log("[SEPOL] su setenforce failed — will use binder hook bypass")
        return false
    }
}

/**
 * Virtual service registration: hook ServiceManager.getService/checkService
 * to return our MockLocationBinder for "service_fl_ml" queries.
 * This completely bypasses the native servicemanager SELinux check.
 */
internal fun ModuleMain.installVirtualServiceHook() {
    val serviceNames = setOf("service_fl_ml")
    try {
        val smClass = Class.forName("android.os.ServiceManager")

        // Hook getService/checkService to return our binder when the service
        // hasn't been registered in native servicemanager yet
        for (m in smClass.declaredMethods) {
            if (m.name != "getService" && m.name != "checkService") continue
            if (m.parameterTypes.size != 1 || m.parameterTypes[0] != String::class.java) continue

            XposedBridge.hookMethod(m, object : XC_MethodHook() {
                override fun afterHookedMethod(param: MethodHookParam) {
                    try {
                        val name = param.args[0] as? String ?: return
                        if (name !in serviceNames) return
                        // Only intercept if native servicemanager returned null
                        if (param.result != null) return
                        val binder = ourMlBinder
                        if (binder != null) {
                            param.result = binder
                        }
                    } catch (_: Throwable) {}
                }
            })
            log("[SEPOL] hooked ServiceManager.${m.name} for virtual service")
        }

        // NOTE: Do NOT hook addService — suppressing SecurityException would make
        // the FL-RealReg retry thread falsely believe registration succeeded.
        // Let exceptions propagate so it keeps retrying until SELinux is Permissive.

        log("[SEPOL] virtual service hooks installed (getService/checkService only)")
    } catch (e: Throwable) {
        log("[SEPOL] virtual service hook failed: $e")
    }
}
