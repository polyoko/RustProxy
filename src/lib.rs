pub mod tunnel;
pub mod socks5;
pub mod udp;
pub mod tunnel_common;
pub mod security;
pub mod cache;

#[cfg(target_os = "android")]
use jni::objects::{JObject, JString};
#[cfg(target_os = "android")]
use jni::JNIEnv;
#[cfg(target_os = "android")]
use android_logger::Config;
#[cfg(target_os = "android")]
use log::LevelFilter;

#[cfg(target_os = "android")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "android")]
use tokio::sync::mpsc;
#[cfg(target_os = "android")]
use std::sync::Mutex;

#[cfg(target_os = "android")]
static RUNNING: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "android")]
lazy_static::lazy_static! {
    static ref SHUTDOWN_TX: Mutex<Option<mpsc::Sender<()>>> = Mutex::new(None);
    static ref JVM: Mutex<Option<jni::JavaVM>> = Mutex::new(None);
    static ref SERVICE_OBJ: Mutex<Option<jni::objects::GlobalRef>> = Mutex::new(None);
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_barissenel_rustproxy_ProxyForegroundService_startAgent(
    mut env: JNIEnv,
    _this: JObject,
    server_addr: JString,
    agent_id: JString,
    server_pw: JString,
) {
    android_logger::init_once(
        Config::default()
            .with_max_level(LevelFilter::Info)
            .with_tag("RustProxy"),
    );

    let addr: String = env.get_string(&server_addr).expect("Invalid address").into();
    let id: String = env.get_string(&agent_id).expect("Invalid ID").into();
    let s_pw_raw: String = env.get_string(&server_pw).expect("Invalid server_pw").into();

    let s_pw = if s_pw_raw.is_empty() { None } else { Some(s_pw_raw) };

    log::info!("Starting Agent '{}' for {}", id, addr);
    
    RUNNING.store(true, Ordering::SeqCst);
    
    if let Ok(vm) = env.get_java_vm() {
        *JVM.lock().unwrap() = Some(vm);
    }
    if let Ok(global_ref) = env.new_global_ref(_this) {
        *SERVICE_OBJ.lock().unwrap() = Some(global_ref);
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (tx, rx) = mpsc::channel(1);
        {
            let mut lock = SHUTDOWN_TX.lock().unwrap();
            *lock = Some(tx);
        }

        log::info!("Attempting connection to {}...", addr);
        if let Err(e) = tunnel::run_agent(addr.clone(), id.clone(), s_pw.clone(), Some(rx)).await {
            log::error!("Agent failed: {}", e);
        } else {
            log::warn!("Agent session ended or stopped.");
        }
    });

    log::info!("Agent thread returning to Kotlin.");
}

#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_barissenel_rustproxy_ProxyForegroundService_stopAgent(
    _env: JNIEnv,
    _this: JObject,
) {
    log::info!("Stopping Agent signal received");
    RUNNING.store(false, Ordering::SeqCst);
    let mut lock = SHUTDOWN_TX.lock().unwrap();
    if let Some(tx) = lock.take() {
        let _ = tx.try_send(());
    }
    *JVM.lock().unwrap() = None;
    *SERVICE_OBJ.lock().unwrap() = None;
}

#[cfg(target_os = "android")]
pub fn trigger_flight_mode_reset() {
    log::info!("trigger_flight_mode_reset called from Rust loop");
    let jvm_guard = JVM.lock().unwrap();
    let service_guard = SERVICE_OBJ.lock().unwrap();
    
    if let (Some(jvm), Some(service)) = (jvm_guard.as_ref(), service_guard.as_ref()) {
        match jvm.attach_current_thread() {
            Ok(mut env) => {
                if let Err(e) = env.call_method(service, "resetIpViaAssistant", "()V", &[]) {
                    log::error!("Failed to call resetIpViaAssistant: {:?}", e);
                } else {
                    log::info!("Successfully invoked resetIpViaAssistant");
                }
            }
            Err(e) => {
                log::error!("Failed to attach thread for JNI: {:?}", e);
            }
        }
    } else {
        log::error!("JVM or SERVICE_OBJ not found. Cannot trigger flight mode reset.");
    }
}
