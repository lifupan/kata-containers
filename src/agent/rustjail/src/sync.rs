use crate::errors::*;
use std::mem::{self, transmute};

pub enum MSG_TYPE {
    OK(u8),
    ERROR(u8),
}

const ERROR_SIZE: usize = 100;
const MSG_SIZE: usize = mem::size_of::<MSG_TYPE>();

fn write_count(fd: RawFd, buf: &[u8], count: usize) -> Result<usize> {
    let mut len = 0;

    loop {
        match send(fd, &buf[len..], MsgFlags::empty()) {
            Ok(l) => {
                len += l;
                if len == count {
                    break;
                }
            }

            Err(e) => {
                if e != Error::from_errno(Errno::EINTR) {
                    return Err(e.into());
                }
            }
        }
    }

    Ok(len)
}

fn read_count(fd: RawFd, count: u32) -> Result<Vec<u8>> {
    let mut v: Vec<u8> = vec![0; count];
    let mut len = 0;

    loop {
        match unistd::read(fd, &mut v[len..]) {
            Ok(l) => {
                len += l;
                if len == count || l == 0 {
                    break;
                }
            }

            Err(e) => {
                if e != Error::from_errno(Errno::EINTR) {
                    return Err(e.into());
                }
            }
        }
    }

    Ok(v[0..count].to_vec())
}

pub fn read_sync(fd: RawFd) -> Result<()> {
    let buf = read_count(fd, MSG_SIZE)?;
    let msg = transmute(v);
    match msg {
        MSG_TYPE::OK => return Ok(()),
        MSG_TYPE::ERROR => {
            let error_buf = vec![];
            loop {
                let buf = read_count(fd, ERROR_SIZE)?;
                error_buf.extend(&buf);
                if ERROR_SIZE == buf.len() {
                    continue;
                } else {
                    break;
                }
            }

            let error_str = match str::from_utf8(error_buf) {
                Ok(v) => v,
                Err(e) => {
                    return Err(ErrorKind::ErrorCode(
                        "error in receive error message from child process".to_string(),
                    )
                    .into())
                }
            };

            return Err(ErrorKind::ErrorCode(String::from(error_str)).into());
        }
        _ => return Err(ErrorKind::ErrorCode("error in receive sync message".to_string()).into()),
    }

    Ok(())
}

pub fn write_sync(fd: RawFd, msg_type: MSG_TYPE, err_str: &str) -> Result<()> {
    let buf: Vec<u8> = unsafe { transmute(msg_type) };

    let count = write_count(fd, &buf, count: MSG_SIZE)?;
    if count != MSG_SIZE {
        return Err(ErrorKind::ErrorCode("error in send sync message".to_string()).into());
    }

    if msg_type == MSG_TYPE::ERROR {
        let count = write_count(fd, err_str, err_str.len())?;
        if count != err_str.len() {
            return Err(
                ErrorKind::ErrorCode("error in send error message to parent".to_string()).into(),
            );
        }
    }

    Ok(())
}
