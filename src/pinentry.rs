use std::{
    ffi::{OsStr, OsString},
    process::Stdio,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt as _},
    process::{Child, ChildStdin, ChildStdout, Command},
};

use crate::{
    error::{Error, Result},
    locked::LockedVec,
};

struct Pinentry<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> {
    child: Option<Child>,
    reader: R,
    writer: W,
}

async fn secure_read_line<R: AsyncRead + Unpin>(reader: &mut R) -> Result<LockedVec> {
    let mut v = LockedVec::new();

    loop {
        let b = reader.read_u8().await?;

        if b == b'\n' {
            break;
        }

        // NOTE: This panics if the line is > 4096 bytes
        v.push(b);
    }

    Ok(v)
}

impl Pinentry<ChildStdout, ChildStdin> {
    async fn spawn(
        binary: &str,
        environment: &crate::protocol::Environment,
        grab: bool,
    ) -> Result<Self> {
        let mut cmd = Command::new(binary);

        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());

        let env_vars = environment.env_vars();

        cmd.args(Self::calc_args(environment, grab));

        for env_var in &*crate::protocol::ENVIRONMENT_VARIABLES_OS {
            if let Some(val) = env_vars.get(env_var.as_os_str()) {
                cmd.env(env_var, val);
            } else {
                cmd.env_remove(env_var);
            }
        }

        cmd.envs(env_vars);

        let mut child = cmd.spawn().map_err(|source| Error::Spawn { source })?;

        let Some(stdin) = child.stdin.take() else {
            return Err(Error::WriteStdin {
                source: std::io::Error::other("stdin unavailable"),
            });
        };

        let Some(stdout) = child.stdout.take() else {
            return Err(Error::PinentryReadOutput {
                source: std::io::Error::other("stdout unavailable"),
            });
        };

        let mut p = Self {
            child: Some(child),
            reader: stdout,
            writer: stdin,
        };

        let line = secure_read_line(&mut p.reader).await?;

        if line.as_str()?.starts_with("OK") {
            Ok(p)
        } else {
            Err(Error::PinentryErrorMessage {
                error: line.as_str()?.to_string(),
            })
        }
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> Pinentry<R, W> {
    fn calc_args(environment: &crate::protocol::Environment, grab: bool) -> Vec<OsString> {
        let mut args: Vec<OsString> = vec!["--timeout".into(), "0".into()];

        if let Some(tty) = environment.tty() {
            args.extend(["--ttyname".into(), tty.into()]);
        }

        let env_vars = environment.env_vars();

        // Not all pinentry appear to respect the --display flag, so we also keep the environment
        // variable.
        if let Some(display) = env_vars.get(OsStr::new("DISPLAY")) {
            args.extend(["--display".into(), display.into()]);
        }

        if !grab {
            args.push("--no-global-grab".into());
        }

        args
    }

    async fn command(&mut self, command: &str) -> Result<LockedVec> {
        self.writer
            .write_all(format!("{command}\n").as_bytes())
            .await
            .map_err(|source| Error::WriteStdin { source })?;

        loop {
            let mut line = secure_read_line(&mut self.reader).await?;

            let line_str = line.as_str()?;

            if line_str.starts_with("OK") {
                return Ok(line);
            } else if let Some(err) = line_str.strip_prefix("ERR ") {
                let mut split = err.splitn(2, ' ');
                let code = split.next();
                match code {
                    Some("83886179") => {
                        return Err(Error::PinentryCancelled);
                    }
                    _ => {
                        return Err(Error::PinentryErrorMessage {
                            error: err.to_string(),
                        });
                    }
                }
            } else if line_str.starts_with("S ") {
                continue;
            } else if line_str.starts_with("D ") {
                match secure_read_line(&mut self.reader).await?.as_str()? {
                    "OK" => {
                        let len = line.len();
                        let len = percent_decode(&mut line[..len]);

                        return Ok(LockedVec::from_slice(&line[2..len]));
                    }
                    line => {
                        return Err(Error::PinentryErrorMessage {
                            error: line.to_string(),
                        });
                    }
                }
            } else {
                return Err(Error::PinentryErrorMessage {
                    error: line.as_str()?.to_string(),
                });
            }
        }
    }

    async fn wait(mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            drop(self);

            child
                .wait()
                .await
                .map_err(|source| Error::PinentryWait { source })?;
        }

        Ok(())
    }
}

pub async fn getpin(
    pinentry: &str,
    prompt: &str,
    desc: &str,
    err: Option<&str>,
    environment: &crate::protocol::Environment,
    grab: bool,
) -> Result<crate::locked::Password> {
    let mut pinentry = Pinentry::spawn(pinentry, environment, grab).await?;

    pinentry.command("SETTITLE rbw").await?;
    pinentry.command(&format!("SETPROMPT {prompt}")).await?;
    pinentry.command(&format!("SETDESC {desc}")).await?;

    if let Some(err) = err {
        pinentry.command(&format!("SETERROR {err}")).await?;
    }

    let buf = pinentry.command("GETPIN").await?;

    pinentry.wait().await?;

    Ok(crate::locked::Password::new(buf))
}

pub async fn confirm(
    pinentry: &str,
    desc: &str,
    environment: &crate::protocol::Environment,
    grab: bool,
) -> Result<bool> {
    let mut pinentry = Pinentry::spawn(pinentry, environment, grab).await?;

    pinentry.command("SETTITLE rbw").await?;
    pinentry.command(&format!("SETDESC {desc}")).await?;

    pinentry.command("CONFIRM").await?;

    pinentry.wait().await?;

    Ok(true)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

// not using the percent-encoding crate because it doesn't provide a way to do
// this in-place, and we want the password to always live within the locked
// vec. should really move something like this into the percent-encoding crate
// at some point.
fn percent_decode(buf: &mut [u8]) -> usize {
    let mut ri = 0;
    let mut wi = 0;
    let len = buf.len();

    while ri < len {
        let mut c = buf[ri];

        if c == b'%' && ri + 2 < len {
            if let Some(h) = hex_digit(buf[ri + 1]) {
                if let Some(l) = hex_digit(buf[ri + 2]) {
                    c = h * 0x10 + l;
                    ri += 2;
                }
            }
        }

        buf[wi] = c;

        ri += 1;
        wi += 1;
    }

    wi
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn hex_digit_valid() {
        assert_eq!(hex_digit(b'0'), Some(0));
        assert_eq!(hex_digit(b'9'), Some(9));
        assert_eq!(hex_digit(b'A'), Some(10));
        assert_eq!(hex_digit(b'F'), Some(15));
        assert_eq!(hex_digit(b'a'), Some(10));
        assert_eq!(hex_digit(b'f'), Some(15));
    }

    #[test]
    fn hex_digit_invalid() {
        assert_eq!(hex_digit(b'g'), None);
        assert_eq!(hex_digit(b'G'), None);
        assert_eq!(hex_digit(b'/'), None);
        assert_eq!(hex_digit(b':'), None);
        assert_eq!(hex_digit(b' '), None);
        assert_eq!(hex_digit(b'%'), None);
    }

    #[test]
    fn percent_decode_empty() {
        let mut buf = [];
        assert_eq!(percent_decode(&mut buf), 0);
    }

    #[test]
    fn percent_decode_no_encoding() {
        let mut buf = *b"hello";
        assert_eq!(percent_decode(&mut buf), 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn percent_decode_simple() {
        let mut buf = *b"%20";
        assert_eq!(percent_decode(&mut buf), 1);
        assert_eq!(&buf[..1], b" ");
    }

    #[test]
    fn percent_decode_uppercase() {
        let mut buf = *b"%4A";
        assert_eq!(percent_decode(&mut buf), 1);
        assert_eq!(&buf[..1], b"J");
    }

    #[test]
    fn percent_decode_lowercase() {
        let mut buf = *b"%4a";
        assert_eq!(percent_decode(&mut buf), 1);
        assert_eq!(&buf[..1], b"J");
    }

    #[test]
    fn percent_decode_mixed() {
        let mut buf = *b"a%20b";
        assert_eq!(percent_decode(&mut buf), 3);
        assert_eq!(&buf[..3], b"a b");
    }

    #[test]
    fn percent_decode_multiple() {
        let mut buf = *b"%20%21";
        assert_eq!(percent_decode(&mut buf), 2);
        assert_eq!(&buf[..2], b" !");
    }

    #[test]
    fn percent_decode_truncated_percent() {
        let mut buf = *b"%";
        assert_eq!(percent_decode(&mut buf), 1);
        assert_eq!(&buf[..1], b"%");
    }

    #[test]
    fn percent_decode_truncated_pair() {
        let mut buf = *b"%2";
        assert_eq!(percent_decode(&mut buf), 2);
        assert_eq!(&buf[..2], b"%2");
    }

    #[test]
    fn percent_decode_invalid_hex() {
        let mut buf = *b"%ZZ";
        assert_eq!(percent_decode(&mut buf), 3);
        assert_eq!(&buf[..3], b"%ZZ");
    }

    #[test]
    fn percent_decode_invalid_second_digit() {
        let mut buf = *b"%0G";
        assert_eq!(percent_decode(&mut buf), 3);
        assert_eq!(&buf[..3], b"%0G");
    }

    #[test]
    fn percent_decode_invalid_first_digit() {
        let mut buf = *b"%G0";
        assert_eq!(percent_decode(&mut buf), 3);
        assert_eq!(&buf[..3], b"%G0");
    }

    #[tokio::test]
    async fn test_secure_read_line() {
        let x = secure_read_line(&mut Cursor::new("ciao\n")).await.unwrap();
        assert_eq!(x.as_str().unwrap(), "ciao");
    }
}
