// reimplement the macros to access the control messages in a MSGHDR structure. These are not currently available in windows-rs library.

use std::mem::size_of;
use std::ptr::null_mut;
use windows::Win32::Networking::WinSock::{CMSGHDR, WSAMSG};

pub fn cmsg_firsthdr(msg: &WSAMSG) -> *mut CMSGHDR {
    if msg.Control.len == 0 {
        return null_mut();
    }

    let cmsg = msg.Control.buf.as_ptr() as *mut CMSGHDR;

    if unsafe { (*cmsg).cmsg_len } < size_of::<CMSGHDR>() {
        null_mut()
    } else {
        cmsg
    }
}

pub fn cmsg_align(len: usize) -> usize {
    (len + size_of::<usize>() - 1) & !(size_of::<usize>() - 1)
}

pub fn cmsg_nxthdr(msg: &WSAMSG, cmsg: *mut CMSGHDR) -> *mut CMSGHDR {
    if cmsg.is_null() {
        return null_mut();
    }

    let eonext = unsafe { cmsg.byte_offset(cmsg_align((*cmsg).cmsg_len) as isize).offset(1) } as usize;
    let eobuf = unsafe { msg.Control.buf.as_ptr().byte_offset(msg.Control.len as isize) } as usize;

    if eonext > eobuf {
        return null_mut();
    }

    let next = unsafe { cmsg.byte_offset(cmsg_align((*cmsg).cmsg_len) as isize) };
    if unsafe { (*next).cmsg_len } < size_of::<CMSGHDR>() {
        null_mut()
    } else {
        next
    }
}

pub fn cmsg_data(cmsg: *mut CMSGHDR) -> *mut u8 {
    unsafe { cmsg.add(1) as *mut u8 }
}

#[cfg(test)]
mod tests {
    use windows::core::PSTR;
    use windows::Win32::Networking::WinSock::WSABUF;

    use super::*;

    #[test]
    fn test_cmsg_firsthdr() {
        let msg = WSAMSG {
            name: null_mut(),
            namelen: 0,
            lpBuffers: null_mut(),
            dwBufferCount: 0,
            Control: WSABUF { len: 0, buf: PSTR::null() },
            dwFlags: 0,
        };

        let cmsg = cmsg_firsthdr(&msg);
        assert_eq!(cmsg, null_mut());
    }

    #[test]
    fn test_cmsg_firsthdr_with_control() {
        let cmsghdr = CMSGHDR {
            cmsg_len: size_of::<CMSGHDR>(),
            cmsg_level: 0,
            cmsg_type: 0,
        };

        let msg = WSAMSG {
            name: null_mut(),
            namelen: 0,
            lpBuffers: null_mut(),
            dwBufferCount: 0,
            Control: WSABUF {
                len: size_of::<CMSGHDR>() as u32,
                buf: PSTR::from_raw(&cmsghdr as *const _ as *mut _),
            },
            dwFlags: 0,
        };

        let cmsg = cmsg_firsthdr(&msg);
        assert_eq!(cmsg, &cmsghdr as *const _ as *mut _);
    }

    #[test]
    fn test_align_returns_multiple_of_ulong_size() {
        for len in 0..100 {
            let aligned_len = cmsg_align(len);
            assert!(aligned_len >= len);
            assert!(aligned_len < len + size_of::<usize>());
            assert_eq!(aligned_len % size_of::<usize>(), 0);
        }
    }

    #[test]
    fn test_cmsg_next_on_array_of_three_cmsg() {
        let mut buffer = [0u8; 128];
        let mut cmsg: *mut CMSGHDR = buffer.as_ptr() as *mut _;

        unsafe {
            for len in [0, 1, 3, 7, 8] {
                (*cmsg).cmsg_type = len as i32;
                (*cmsg).cmsg_len = size_of::<CMSGHDR>() + len;
                cmsg = cmsg.add(1);
                cmsg = cmsg.byte_offset(cmsg_align(len) as isize)
            }
        }

        let final_length = unsafe { cmsg.byte_offset_from(buffer.as_ptr()) };

        let msg = WSAMSG {
            name: null_mut(),
            namelen: 0,
            lpBuffers: null_mut(),
            dwBufferCount: 0,
            Control: WSABUF {
                len: final_length as u32,
                buf: PSTR::from_raw(buffer.as_ptr() as *mut _),
            },
            dwFlags: 0,
        };

        unsafe {
            let cmsg = cmsg_firsthdr(&msg);
            assert_eq!(unsafe { cmsg.byte_offset_from(buffer.as_ptr()) }, 0);
            assert_eq!((*cmsg).cmsg_type, 0);

            let cmsg = cmsg_nxthdr(&msg, cmsg);
            assert_ne!(cmsg, null_mut());
            assert_eq!(unsafe { cmsg.byte_offset_from(buffer.as_ptr()) }, size_of::<CMSGHDR>() as isize);
            assert_eq!((*cmsg).cmsg_type, 1);
            assert_eq!((*cmsg).cmsg_len, size_of::<CMSGHDR>() + 1);
            let datasize = cmsg_align(1);

            let cmsg = cmsg_nxthdr(&msg, cmsg);
            assert_ne!(cmsg, null_mut());
            assert_eq!(
                unsafe { cmsg.byte_offset_from(buffer.as_ptr()) },
                2 * size_of::<CMSGHDR>() as isize + datasize as isize
            );
            assert_eq!((*cmsg).cmsg_type, 3);
            assert_eq!((*cmsg).cmsg_len, size_of::<CMSGHDR>() + 3);
            let datasize = datasize + cmsg_align(3);

            let cmsg = cmsg_nxthdr(&msg, cmsg);
            assert_ne!(cmsg, null_mut());
            assert_eq!(
                unsafe { cmsg.byte_offset_from(buffer.as_ptr()) },
                3 * size_of::<CMSGHDR>() as isize + datasize as isize
            );
            assert_eq!((*cmsg).cmsg_type, 7);
            assert_eq!((*cmsg).cmsg_len, size_of::<CMSGHDR>() + 7);
            let datasize = datasize + cmsg_align(7);

            let cmsg = cmsg_nxthdr(&msg, cmsg);
            assert_ne!(cmsg, null_mut());
            assert_eq!(
                unsafe { cmsg.byte_offset_from(buffer.as_ptr()) },
                4 * size_of::<CMSGHDR>() as isize + datasize as isize
            );
            assert_eq!((*cmsg).cmsg_type, 8);
            assert_eq!((*cmsg).cmsg_len, size_of::<CMSGHDR>() + 8);
            let datasize = datasize + cmsg_align(8);

            let cmsg = cmsg_nxthdr(&msg, cmsg);
            assert_eq!(cmsg, null_mut());
        }
    }

    #[test]
    fn cmsg_next_returns_null_on_empty_cmsghdr() {
        let buffer = [0u8; 128];

        let msg = WSAMSG {
            name: null_mut(),
            namelen: 0,
            lpBuffers: null_mut(),
            dwBufferCount: 0,
            Control: WSABUF {
                len: size_of::<CMSGHDR>() as u32,
                buf: PSTR::from_raw(buffer.as_ptr() as *mut _),
            },
            dwFlags: 0,
        };

        let cmsg = cmsg_firsthdr(&msg);
        assert_eq!(cmsg, null_mut());

        let cmsg = cmsg_nxthdr(&msg, cmsg);
        assert_eq!(cmsg, null_mut());
    }

    #[test]
    fn cmsg_next_returns_null_on_empty_cmsghdr_after_one() {
        let mut buffer = [0u8; 128];
        unsafe {
            let cmsg = buffer.as_mut_ptr() as *mut CMSGHDR;
            (*cmsg).cmsg_len = size_of::<CMSGHDR>();
            (*cmsg).cmsg_type = 22;
        }

        let msg = WSAMSG {
            name: null_mut(),
            namelen: 0,
            lpBuffers: null_mut(),
            dwBufferCount: 0,
            Control: WSABUF {
                len: size_of::<CMSGHDR>() as u32,
                buf: PSTR::from_raw(buffer.as_ptr() as *mut _),
            },
            dwFlags: 0,
        };

        let cmsg = cmsg_firsthdr(&msg);
        assert_ne!(cmsg, null_mut());

        let cmsg = cmsg_nxthdr(&msg, cmsg);
        assert_eq!(cmsg, null_mut());
    }
}
