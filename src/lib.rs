pub mod cache;
pub mod http_proxy;
pub mod security;
pub mod session;
pub mod socks5;
pub mod tls;
pub mod tunnel;
pub mod tunnel_common;
pub mod udp;

#[cfg(target_os = "android")]
use android_logger::Config;
#[cfg(target_os = "android")]
use jni::{
    objects::{GlobalRef, JObject, JString, JValue},
    sys::{jint, JNI_VERSION_1_6},
    JNIEnv, JavaVM, NativeMethod,
};
#[cfg(target_os = "android")]
use log::LevelFilter;
#[cfg(target_os = "android")]
use std::{
    ffi::c_void,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
#[cfg(target_os = "android")]
use tokio::sync::mpsc;

#[cfg(target_os = "android")]
const SERVICE_CLASS: &str = "me/uii/rustproxy/ProxyForegroundService";

#[cfg(target_os = "android")]
static RUNNING: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "android")]
lazy_static::lazy_static! {
    static ref SHUTDOWN_TX: Mutex<Option<mpsc::Sender<()>>> = Mutex::new(None);
    static ref JVM: Mutex<Option<Arc<JavaVM>>> = Mutex::new(None);
    static ref SERVICE_OBJ: Mutex<Option<GlobalRef>> = Mutex::new(None);
}

/// The Android service receives state changes instead of scraping logcat.
#[cfg(target_os = "android")]
pub(crate) fn report_android_status(state: &str, error: Option<&str>) {
    let (jvm, service) = (
        JVM.lock().ok().and_then(|value| value.clone()),
        SERVICE_OBJ.lock().ok().and_then(|value| value.clone()),
    );
    let (Some(jvm), Some(service)) = (jvm, service) else {
        return;
    };

    let payload = serde_json::json!({ "state": state, "error": error }).to_string();
    let Ok(mut env) = jvm.attach_current_thread() else {
        return;
    };
    let Ok(payload) = env.new_string(payload) else {
        return;
    };
    let payload = JObject::from(payload);
    if let Err(error) = env.call_method(
        service.as_obj(),
        "onStatus",
        "(Ljava/lang/String;)V",
        &[JValue::Object(&payload)],
    ) {
        log::error!("Failed to deliver Android status: {error:?}");
    }
}

#[cfg(target_os = "android")]
pub(crate) fn collect_android_device_status() -> Option<String> {
    let (jvm, service) = (
        JVM.lock().ok().and_then(|value| value.clone()),
        SERVICE_OBJ.lock().ok().and_then(|value| value.clone()),
    );
    let (Some(jvm), Some(service)) = (jvm, service) else {
        return None;
    };
    let mut env = jvm.attach_current_thread().ok()?;
    let value = env
        .call_method(
            service.as_obj(),
            "getDeviceStatusJson",
            "()Ljava/lang/String;",
            &[],
        )
        .ok()?
        .l()
        .ok()?;
    if value.is_null() {
        return None;
    }
    env.get_string(&JString::from(value)).ok().map(Into::into)
}

#[cfg(not(target_os = "android"))]
pub(crate) fn report_android_status(_: &str, _: Option<&str>) {}

#[cfg(target_os = "android")]
fn service_cache_path(env: &mut JNIEnv, service: &JObject) -> Result<String, String> {
    let value = env
        .call_method(service, "getCacheDirPath", "()Ljava/lang/String;", &[])
        .map_err(|error| format!("cannot read app files directory: {error:?}"))?
        .l()
        .map_err(|error| format!("invalid app files directory: {error:?}"))?;
    if value.is_null() {
        return Err("app files directory is unavailable".into());
    }
    let value = JString::from(value);
    let directory: String = env
        .get_string(&value)
        .map_err(|error| format!("invalid app files directory: {error:?}"))?
        .into();
    if directory.is_empty() {
        return Err("app files directory is unavailable".into());
    }
    Ok(format!("{directory}/agent_cache.json"))
}

#[cfg(target_os = "android")]
fn service_fingerprint(env: &mut JNIEnv, service: &JObject) -> Result<Option<String>, String> {
    let value = env
        .call_method(service, "getServerFingerprint", "()Ljava/lang/String;", &[])
        .map_err(|error| format!("cannot read server fingerprint: {error:?}"))?
        .l()
        .map_err(|error| format!("invalid server fingerprint: {error:?}"))?;
    if value.is_null() {
        return Ok(None);
    }
    let value = JString::from(value);
    let value: String = env
        .get_string(&value)
        .map_err(|error| format!("invalid server fingerprint: {error:?}"))?
        .into();
    Ok((!value.trim().is_empty()).then_some(value))
}

#[cfg(target_os = "android")]
fn start_agent_inner(
    mut env: JNIEnv,
    service: JObject,
    server_addr: JString,
    agent_id: JString,
    server_pw: JString,
) {
    android_logger::init_once(
        Config::default()
            .with_max_level(LevelFilter::Info)
            .with_tag("RustProxy"),
    );

    let Ok(vm) = env.get_java_vm() else {
        return;
    };
    let Ok(service_ref) = env.new_global_ref(&service) else {
        return;
    };
    *JVM.lock().unwrap() = Some(Arc::new(vm));
    *SERVICE_OBJ.lock().unwrap() = Some(service_ref);

    let read_string = |env: &mut JNIEnv, value: JString, name: &str| {
        env.get_string(&value)
            .map(|value| value.into())
            .map_err(|error| format!("invalid {name}: {error:?}"))
    };
    let addr: String = match read_string(&mut env, server_addr, "address") {
        Ok(value) => value,
        Err(error) => {
            report_android_status("disconnected", Some(&error));
            return;
        }
    };
    let id: String = match read_string(&mut env, agent_id, "agent ID") {
        Ok(value) if !value.is_empty() => value,
        Ok(_) => {
            report_android_status("disconnected", Some("agent ID is required"));
            return;
        }
        Err(error) => {
            report_android_status("disconnected", Some(&error));
            return;
        }
    };
    let password: String = match read_string(&mut env, server_pw, "password") {
        Ok(value) => value,
        Err(error) => {
            report_android_status("disconnected", Some(&error));
            return;
        }
    };
    let cache_path = match service_cache_path(&mut env, &service) {
        Ok(path) => path,
        Err(error) => {
            report_android_status("disconnected", Some(&error));
            return;
        }
    };
    let fingerprint = match service_fingerprint(&mut env, &service) {
        Ok(value) => value,
        Err(error) => {
            report_android_status("disconnected", Some(&error));
            return;
        }
    };

    if RUNNING.swap(true, Ordering::SeqCst) {
        log::warn!("Agent is already running; ignoring duplicate start request.");
        return;
    }
    report_android_status("connecting", None);

    let password = (!password.is_empty()).then_some(password);
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            RUNNING.store(false, Ordering::SeqCst);
            report_android_status("disconnected", Some(&format!("runtime failed: {error}")));
            return;
        }
    };
    runtime.block_on(async {
        let (tx, rx) = mpsc::channel(1);
        *SHUTDOWN_TX.lock().unwrap() = Some(tx);
        if let Err(error) =
            tunnel::run_agent_with_cache_path(addr, id, password, Some(rx), cache_path, fingerprint)
                .await
        {
            log::error!("Agent failed: {error}");
            report_android_status("disconnected", Some(&error.to_string()));
        }
    });

    RUNNING.store(false, Ordering::SeqCst);
    SHUTDOWN_TX.lock().unwrap().take();
    log::info!("Agent thread returned to Kotlin.");
}

#[cfg(target_os = "android")]
extern "system" fn start_agent(
    env: JNIEnv,
    service: JObject,
    server_addr: JString,
    agent_id: JString,
    server_pw: JString,
) {
    if catch_unwind(AssertUnwindSafe(|| {
        start_agent_inner(env, service, server_addr, agent_id, server_pw)
    }))
    .is_err()
    {
        RUNNING.store(false, Ordering::SeqCst);
        report_android_status("disconnected", Some("Rust agent stopped unexpectedly"));
    }
}

#[cfg(target_os = "android")]
fn stop_agent_inner() {
    log::info!("Stopping Agent signal received");
    RUNNING.store(false, Ordering::SeqCst);
    if let Some(tx) = SHUTDOWN_TX.lock().unwrap().take() {
        let _ = tx.try_send(());
    }
    report_android_status("disconnected", None);
    *JVM.lock().unwrap() = None;
    *SERVICE_OBJ.lock().unwrap() = None;
}

#[cfg(target_os = "android")]
extern "system" fn stop_agent(_: JNIEnv, _: JObject) {
    let _ = catch_unwind(AssertUnwindSafe(stop_agent_inner));
}

/// Register natives so the package can be renamed without changing Rust symbols.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn JNI_OnLoad(vm: JavaVM, _: *mut c_void) -> jint {
    let Ok(mut env) = vm.get_env() else {
        return 0;
    };
    let Ok(class) = env.find_class(SERVICE_CLASS) else {
        return 0;
    };
    let methods = [
        NativeMethod {
            name: "startAgent".into(),
            sig: "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V".into(),
            fn_ptr: start_agent as *mut c_void,
        },
        NativeMethod {
            name: "stopAgent".into(),
            sig: "()V".into(),
            fn_ptr: stop_agent as *mut c_void,
        },
    ];
    if env.register_native_methods(class, &methods).is_err() {
        return 0;
    }
    JNI_VERSION_1_6
}

#[cfg(target_os = "android")]
pub fn trigger_flight_mode_reset() {
    let (jvm, service) = (
        JVM.lock().ok().and_then(|value| value.clone()),
        SERVICE_OBJ.lock().ok().and_then(|value| value.clone()),
    );
    if let (Some(jvm), Some(service)) = (jvm, service) {
        match jvm.attach_current_thread() {
            Ok(mut env) => {
                if let Err(error) =
                    env.call_method(service.as_obj(), "resetIpViaAssistant", "()V", &[])
                {
                    log::error!("Failed to call resetIpViaAssistant: {error:?}");
                }
            }
            Err(error) => log::error!("Failed to attach thread for JNI: {error:?}"),
        }
    } else {
        log::error!("JVM or service is unavailable; cannot reset IP.");
    }
}
