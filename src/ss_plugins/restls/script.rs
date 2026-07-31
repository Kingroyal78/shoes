// Restls-Script grammar derived from 3andne/restls (BSD-3-Clause).

use std::{fmt, io, str::FromStr};

use rand::RngExt;

const MAX_SCRIPT_BYTES: usize = 4096;
const MAX_SCRIPT_LINES: usize = 256;
pub const MAX_SCRIPT_TARGET: u16 = 32768;
/// Default used by `metacubex/restls-client-go` v0.1.8 for both client and
/// server configurations when `restls-script` is empty.
pub const MIHOMO_DEFAULT_RESTLS_SCRIPT: &str = "250?100<1,350~100<1,600~100,300~200,300~100";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestlsCommand {
    Noop,
    Response(u8),
}

impl RestlsCommand {
    pub fn encode(self) -> [u8; 2] {
        match self {
            Self::Noop => [0, 0],
            Self::Response(count) => [1, count],
        }
    }

    pub fn decode(bytes: [u8; 2]) -> io::Result<Self> {
        match bytes {
            [0, 0] => Ok(Self::Noop),
            [1, count] => Ok(Self::Response(count)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported or malformed Restls command",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetLength {
    Fixed(u16),
    PerRecord { base: u16, range: u16 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScriptLine {
    target: TargetLength,
    pub command: RestlsCommand,
}

impl ScriptLine {
    pub fn target_len(&self) -> usize {
        match self.target {
            TargetLength::Fixed(length) => length as usize,
            TargetLength::PerRecord { base, range } => {
                base as usize + rand::rng().random_range(0..range as usize)
            }
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RestlsScript(Vec<ScriptLine>);

impl RestlsScript {
    pub fn line(&self, index: usize) -> Option<&ScriptLine> {
        self.0.get(index)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn mihomo_default() -> Result<Self, ScriptParseError> {
        MIHOMO_DEFAULT_RESTLS_SCRIPT.parse()
    }

    fn parse_with_rng(
        input: &str,
        mut sample_frozen: impl FnMut(u16) -> u16,
    ) -> Result<Self, ScriptParseError> {
        if input.len() > MAX_SCRIPT_BYTES {
            return Err(ScriptParseError::new("script exceeds 4096 bytes"));
        }
        let compact: String = input
            .chars()
            .filter(|character| *character != ' ')
            .collect();
        if compact.is_empty() {
            return Ok(Self::default());
        }

        let raw_lines: Vec<&str> = compact.split(',').collect();
        if raw_lines.len() > MAX_SCRIPT_LINES {
            return Err(ScriptParseError::new("script has more than 256 lines"));
        }
        let mut lines = Vec::with_capacity(raw_lines.len());
        for raw in raw_lines {
            if raw.is_empty() {
                return Err(ScriptParseError::new("script contains an empty line"));
            }
            lines.push(parse_line(raw, &mut sample_frozen)?);
        }
        Ok(Self(lines))
    }
}

impl FromStr for RestlsScript {
    type Err = ScriptParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = if input.trim().is_empty() {
            MIHOMO_DEFAULT_RESTLS_SCRIPT
        } else {
            input
        };
        Self::parse_with_rng(input, |range| rand::rng().random_range(0..range))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptParseError {
    message: &'static str,
}

impl ScriptParseError {
    fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl fmt::Display for ScriptParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for ScriptParseError {}

fn parse_line(
    raw: &str,
    sample_frozen: &mut impl FnMut(u16) -> u16,
) -> Result<ScriptLine, ScriptParseError> {
    let bytes = raw.as_bytes();
    let (base, mut cursor) = parse_number(bytes, 0)?;
    let mut target = TargetLength::Fixed(base);

    if let Some(marker @ (b'?' | b'~')) = bytes.get(cursor).copied() {
        cursor += 1;
        let (range, next) = parse_number(bytes, cursor)?;
        cursor = next;
        if range == 0 {
            return Err(ScriptParseError::new(
                "random target range must be greater than zero",
            ));
        }
        if u32::from(base) + u32::from(range) > u32::from(MAX_SCRIPT_TARGET) {
            return Err(ScriptParseError::new(
                "random target exceeds the Restls limit",
            ));
        }
        target = if marker == b'?' {
            let sampled = sample_frozen(range);
            if sampled >= range {
                return Err(ScriptParseError::new(
                    "random sampler returned an out-of-range value",
                ));
            }
            TargetLength::Fixed(base + sampled)
        } else {
            TargetLength::PerRecord { base, range }
        };
    }

    let command = if cursor == bytes.len() {
        RestlsCommand::Noop
    } else {
        if bytes[cursor] != b'<' {
            return Err(ScriptParseError::new("unsupported Restls script operator"));
        }
        let (count, next) = parse_number(bytes, cursor + 1)?;
        if next != bytes.len() {
            return Err(ScriptParseError::new(
                "trailing bytes after Restls response command",
            ));
        }
        let count =
            u8::try_from(count).map_err(|_| ScriptParseError::new("response count exceeds 255"))?;
        RestlsCommand::Response(count)
    };

    Ok(ScriptLine { target, command })
}

fn parse_number(bytes: &[u8], start: usize) -> Result<(u16, usize), ScriptParseError> {
    let mut cursor = start;
    let mut value = 0u32;
    while let Some(digit @ b'0'..=b'9') = bytes.get(cursor).copied() {
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(digit - b'0')))
            .ok_or_else(|| ScriptParseError::new("numeric value overflow"))?;
        if value > u32::from(MAX_SCRIPT_TARGET) {
            return Err(ScriptParseError::new(
                "numeric value exceeds the Restls limit",
            ));
        }
        cursor += 1;
    }
    if cursor == start {
        return Err(ScriptParseError::new("expected a decimal number"));
    }
    Ok((value as u16, cursor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_script_operators_without_panicking() {
        let script = RestlsScript::parse_with_rng("200?10, 300~50,70<2,100~1000<1", |_| 7).unwrap();
        assert_eq!(script.len(), 4);
        assert_eq!(script.line(0).unwrap().target_len(), 207);
        assert_eq!(script.line(2).unwrap().command, RestlsCommand::Response(2));
    }

    #[test]
    fn rejects_ambiguous_or_dangerous_input() {
        for invalid in [
            ",",
            "10,,20",
            "10?0",
            "32768~1",
            "10>2",
            "10<256",
            "10<1garbage",
            "x",
        ] {
            assert!(invalid.parse::<RestlsScript>().is_err(), "{invalid}");
        }
    }

    #[test]
    fn command_decoder_is_strict() {
        assert_eq!(
            RestlsCommand::decode([1, 3]).unwrap(),
            RestlsCommand::Response(3)
        );
        assert!(RestlsCommand::decode([0, 1]).is_err());
        assert!(RestlsCommand::decode([2, 0]).is_err());
    }

    #[test]
    fn empty_script_uses_the_mihomo_server_default() {
        let script = "".parse::<RestlsScript>().unwrap();
        assert_eq!(script.len(), 5);

        let first = script.line(0).unwrap();
        assert!((250..350).contains(&first.target_len()));
        assert_eq!(first.command, RestlsCommand::Response(1));

        let second = script.line(1).unwrap();
        assert!((350..450).contains(&second.target_len()));
        assert_eq!(second.command, RestlsCommand::Response(1));

        assert!((600..700).contains(&script.line(2).unwrap().target_len()));
        assert!((300..500).contains(&script.line(3).unwrap().target_len()));
        assert!((300..400).contains(&script.line(4).unwrap().target_len()));
    }
}
