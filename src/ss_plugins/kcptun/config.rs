use std::fmt;
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KcptunCrypt {
    Aes,
    Aes128,
    Aes192,
    Aes128Gcm,
    Salsa20,
    Blowfish,
    Twofish,
    Cast5,
    TripleDes,
    Tea,
    Xtea,
    Xor,
    None,
    Null,
}

impl KcptunCrypt {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "aes" => Ok(Self::Aes),
            "aes-128" => Ok(Self::Aes128),
            "aes-192" => Ok(Self::Aes192),
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "salsa20" => Ok(Self::Salsa20),
            "blowfish" => Ok(Self::Blowfish),
            "twofish" => Ok(Self::Twofish),
            "cast5" => Ok(Self::Cast5),
            "3des" => Ok(Self::TripleDes),
            "tea" => Ok(Self::Tea),
            "xtea" => Ok(Self::Xtea),
            "xor" => Ok(Self::Xor),
            "none" => Ok(Self::None),
            "null" => Ok(Self::Null),
            _ => Err(invalid(format!("unsupported Kcptun crypt `{value}`"))),
        }
    }

    pub fn minimum_mtu(self) -> u16 {
        match self {
            Self::Null => 58,
            Self::Aes128Gcm => 86,
            _ => 78,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KcptunMode {
    Normal,
    Fast,
    Fast2,
    Fast3,
    Manual,
}

impl KcptunMode {
    pub fn parse(value: &str) -> io::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "normal" => Ok(Self::Normal),
            "fast" => Ok(Self::Fast),
            "fast2" => Ok(Self::Fast2),
            "fast3" => Ok(Self::Fast3),
            "manual" => Ok(Self::Manual),
            _ => Err(invalid(format!("unsupported Kcptun mode `{value}`"))),
        }
    }
}

/// Server-owned Kcptun settings exposed by V2Board schema v1.
///
/// Client pool/scavenger settings are intentionally absent: they are not part
/// of the backend manifest and must never influence server readiness.
#[derive(Clone, PartialEq, Eq)]
pub struct KcptunConfig {
    pub key: String,
    pub crypt: KcptunCrypt,
    pub mode: KcptunMode,
    pub mtu: u16,
    pub rate_limit: u32,
    pub send_window: u32,
    pub receive_window: u32,
    pub data_shards: u16,
    pub parity_shards: u16,
    pub dscp: u8,
    pub no_compression: bool,
    pub ack_no_delay: bool,
    pub no_delay: bool,
    pub interval_ms: u32,
    pub resend: u32,
    pub no_congestion: bool,
    pub socket_buffer: u32,
    pub smux_version: u8,
    pub smux_buffer: u32,
    pub frame_size: u16,
    pub stream_buffer: u32,
    pub keepalive_secs: u32,
}

impl fmt::Debug for KcptunConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KcptunConfig")
            .field("key", &"[REDACTED]")
            .field("crypt", &self.crypt)
            .field("mode", &self.mode)
            .field("mtu", &self.mtu)
            .field("rate_limit", &self.rate_limit)
            .field("send_window", &self.send_window)
            .field("receive_window", &self.receive_window)
            .field("data_shards", &self.data_shards)
            .field("parity_shards", &self.parity_shards)
            .field("dscp", &self.dscp)
            .field("no_compression", &self.no_compression)
            .field("ack_no_delay", &self.ack_no_delay)
            .field("no_delay", &self.no_delay)
            .field("interval_ms", &self.interval_ms)
            .field("resend", &self.resend)
            .field("no_congestion", &self.no_congestion)
            .field("socket_buffer", &self.socket_buffer)
            .field("smux_version", &self.smux_version)
            .field("smux_buffer", &self.smux_buffer)
            .field("frame_size", &self.frame_size)
            .field("stream_buffer", &self.stream_buffer)
            .field("keepalive_secs", &self.keepalive_secs)
            .finish()
    }
}

impl Default for KcptunConfig {
    fn default() -> Self {
        Self {
            key: "it's a secrect".to_string(),
            crypt: KcptunCrypt::Aes,
            mode: KcptunMode::Fast,
            mtu: 1350,
            rate_limit: 0,
            send_window: 128,
            receive_window: 512,
            data_shards: 10,
            parity_shards: 3,
            dscp: 0,
            no_compression: false,
            ack_no_delay: false,
            no_delay: false,
            interval_ms: 30,
            resend: 2,
            no_congestion: true,
            socket_buffer: 4_194_304,
            smux_version: 1,
            smux_buffer: 4_194_304,
            frame_size: 8192,
            stream_buffer: 2_097_152,
            keepalive_secs: 10,
        }
    }
}

impl KcptunConfig {
    pub fn apply_mode(&mut self) {
        let Some((no_delay, interval, resend, no_congestion)) = (match self.mode {
            KcptunMode::Normal => Some((false, 40, 2, true)),
            KcptunMode::Fast => Some((false, 30, 2, true)),
            KcptunMode::Fast2 => Some((true, 20, 2, true)),
            KcptunMode::Fast3 => Some((true, 10, 2, true)),
            KcptunMode::Manual => None,
        }) else {
            return;
        };
        self.no_delay = no_delay;
        self.interval_ms = interval;
        self.resend = resend;
        self.no_congestion = no_congestion;
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.key.is_empty() && !matches!(self.crypt, KcptunCrypt::Null) {
            return Err(invalid("Kcptun key must not be empty"));
        }
        if !(self.crypt.minimum_mtu()..=1500).contains(&self.mtu) {
            return Err(invalid(format!(
                "Kcptun mtu must be between {} and 1500 for the selected crypt",
                self.crypt.minimum_mtu()
            )));
        }
        if self.send_window == 0 || self.receive_window == 0 {
            return Err(invalid("Kcptun send/receive windows must be positive"));
        }
        if self.data_shards == 0
            || self.parity_shards == 0
            || u32::from(self.data_shards) + u32::from(self.parity_shards) > 256
        {
            return Err(invalid(
                "Kcptun FEC shards must be positive and total no more than 256",
            ));
        }
        if self.dscp > 63 {
            return Err(invalid("Kcptun DSCP must be between 0 and 63"));
        }
        if !(10..=5000).contains(&self.interval_ms) {
            return Err(invalid(
                "Kcptun interval must be between 10 and 5000 milliseconds",
            ));
        }
        if self.socket_buffer == 0 || self.smux_buffer == 0 {
            return Err(invalid("Kcptun socket and smux buffers must be positive"));
        }
        if !matches!(self.smux_version, 1 | 2) {
            return Err(invalid("Kcptun smux version must be 1 or 2"));
        }
        if self.frame_size == 0 {
            return Err(invalid("Kcptun smux frame size must be positive"));
        }
        if self.stream_buffer == 0 || self.stream_buffer > self.smux_buffer {
            return Err(invalid(
                "Kcptun stream buffer must be positive and no larger than smux buffer",
            ));
        }
        if self.keepalive_secs == 0 {
            return Err(invalid("Kcptun keepalive must be positive"));
        }
        Ok(())
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_every_panel_crypt() {
        for crypt in [
            "aes",
            "aes-128",
            "aes-192",
            "aes-128-gcm",
            "salsa20",
            "blowfish",
            "twofish",
            "cast5",
            "3des",
            "tea",
            "xtea",
            "xor",
            "none",
            "null",
        ] {
            assert!(KcptunCrypt::parse(crypt).is_ok(), "{crypt}");
        }
        assert!(KcptunCrypt::parse("unknown").is_err());
    }

    #[test]
    fn applies_reference_mode_profiles() {
        let expected = [
            (KcptunMode::Normal, false, 40),
            (KcptunMode::Fast, false, 30),
            (KcptunMode::Fast2, true, 20),
            (KcptunMode::Fast3, true, 10),
        ];
        for (mode, no_delay, interval) in expected {
            let mut config = KcptunConfig {
                mode,
                ..Default::default()
            };
            config.apply_mode();
            assert_eq!(config.no_delay, no_delay);
            assert_eq!(config.interval_ms, interval);
            assert_eq!(config.resend, 2);
            assert!(config.no_congestion);
        }
    }

    #[test]
    fn enforces_wire_and_resource_bounds() {
        let mut config = KcptunConfig {
            crypt: KcptunCrypt::Aes128Gcm,
            mtu: 85,
            ..KcptunConfig::default()
        };
        assert!(config.validate().is_err());

        config.mtu = 1350;
        config.data_shards = 255;
        config.parity_shards = 2;
        assert!(config.validate().is_err());

        config.data_shards = 10;
        config.parity_shards = 3;
        config.stream_buffer = config.smux_buffer + 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn debug_output_redacts_packet_key() {
        let config = KcptunConfig {
            key: "super-secret-kcptun-key".to_string(),
            ..KcptunConfig::default()
        };
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret-kcptun-key"));
    }
}
