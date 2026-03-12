use std::fmt::Display;
use std::sync::OnceLock;
use tracing_subscriber::EnvFilter;

pub const DEFAULT_MTU: u32 = 0;
pub const DEFAULT_OBFUSCATION_KEY: u8 = 0;

static CONFIG: OnceLock<SlipstreamConfig> = OnceLock::new();

struct SlipstreamConfig {
    mtu: u32,
    key: u8,
    xor_label: bool,
    xor_data: bool,
}

pub fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .try_init();
}

pub fn unwrap_or_exit<T, E>(result: Result<T, E>, context: &str, code: i32) -> T
where
    E: Display,
{
    result.unwrap_or_else(|err| exit_with_error(context, err, code))
}

pub fn exit_with_error(context: &str, err: impl Display, code: i32) -> ! {
    tracing::error!("{}: {}", context, err);
    std::process::exit(code);
}

pub fn exit_with_message(message: &str, code: i32) -> ! {
    tracing::error!("{}", message);
    std::process::exit(code);
}

pub fn set_config(mtu: u32, key: u8, xor_label: bool, xor_data: bool) {
    let _ = CONFIG.set(SlipstreamConfig {
        mtu,
        key,
        xor_label,
        xor_data,
    });
}

pub fn get_mtu() -> u32 {
    CONFIG.get().map(|c| c.mtu).unwrap_or(DEFAULT_MTU)
}

pub fn get_obfuscation_key() -> u8 {
    CONFIG
        .get()
        .map(|c| c.key)
        .unwrap_or(DEFAULT_OBFUSCATION_KEY)
}

pub fn get_xor_label() -> bool {
    CONFIG.get().map(|c| c.xor_label).unwrap_or(false)
}

pub fn get_xor_data() -> bool {
    CONFIG.get().map(|c| c.xor_data).unwrap_or(false)
}

pub fn parse_hex_u8(input: &str) -> Result<u8, String> {
    if input.starts_with("0x") || input.starts_with("0X") {
        u8::from_str_radix(&input[2..], 16).map_err(|e| e.to_string())
    } else {
        input.parse::<u8>().map_err(|e| e.to_string())
    }
}
