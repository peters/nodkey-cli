//! Terminal echo off while `nodkey secret save` reads a pasted key, so the key does not show on
//! screen or stay in the scrollback. The terminal gets its mode back when the guard drops, and on
//! Unix also when Ctrl-C or a signal to stop ends the program during the read.

/// Echo stays off while this lives.
pub struct NoEcho(imp::Saved);

impl NoEcho {
    /// Turns echo off on stdin. `None` when stdin is not a terminal or its mode cannot change.
    pub fn stdin() -> Option<Self> {
        imp::start_stdin().map(NoEcho)
    }
}

impl Drop for NoEcho {
    fn drop(&mut self) {
        imp::restore(&self.0);
    }
}

#[cfg(unix)]
mod imp {
    use std::sync::OnceLock;

    /// The terminal, its mode before and the signal handlers before.
    pub struct Saved {
        fd: libc::c_int,
        mode: libc::termios,
        handlers: [libc::sighandler_t; 3],
    }

    const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

    /// What the signal handler puts back: the first terminal and mode of this process.
    static FIRST: OnceLock<(libc::c_int, libc::termios)> = OnceLock::new();

    extern "C" fn on_signal(sig: libc::c_int) {
        if let Some((fd, mode)) = FIRST.get() {
            // SAFETY: tcsetattr, signal and raise are async-signal-safe.
            unsafe {
                libc::tcsetattr(*fd, libc::TCSANOW, mode);
            }
        }
        // SAFETY: as above; the default action then ends the program as the signal asked.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }

    pub fn start_stdin() -> Option<Saved> {
        start(libc::STDIN_FILENO)
    }

    /// Turns echo off on the terminal `fd` (the line break of Enter still shows).
    pub fn start(fd: libc::c_int) -> Option<Saved> {
        let mut mode = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: tcgetattr fills `mode` when it returns 0.
        let mode = unsafe {
            if libc::tcgetattr(fd, mode.as_mut_ptr()) != 0 {
                return None;
            }
            mode.assume_init()
        };
        let _ = FIRST.set((fd, mode));
        let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // SAFETY: installs a handler that only calls async-signal-safe functions.
        let handlers = SIGNALS.map(|sig| unsafe { libc::signal(sig, handler) });
        let mut quiet = mode;
        quiet.c_lflag &= !libc::ECHO;
        quiet.c_lflag |= libc::ECHONL;
        let saved = Saved { fd, mode, handlers };
        // SAFETY: `quiet` is a valid termios read from this terminal.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) } != 0 {
            restore(&saved);
            return None;
        }
        Some(saved)
    }

    pub fn restore(saved: &Saved) {
        // SAFETY: puts back the mode and handlers read before.
        unsafe {
            libc::tcsetattr(saved.fd, libc::TCSANOW, &saved.mode);
            for (sig, handler) in SIGNALS.iter().zip(saved.handlers) {
                libc::signal(*sig, handler);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn lflag(fd: libc::c_int) -> libc::tcflag_t {
            let mut mode = std::mem::MaybeUninit::<libc::termios>::uninit();
            // SAFETY: tcgetattr fills `mode` when it returns 0.
            unsafe {
                assert_eq!(libc::tcgetattr(fd, mode.as_mut_ptr()), 0);
                mode.assume_init().c_lflag
            }
        }

        #[test]
        fn echo_goes_off_and_comes_back() {
            let (mut main, mut sub) = (0, 0);
            // SAFETY: openpty writes two file descriptors.
            let made = unsafe {
                libc::openpty(
                    &mut main,
                    &mut sub,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(made, 0, "no pseudo terminal");
            let before = lflag(sub);
            assert_ne!(before & libc::ECHO, 0);
            let saved = start(sub).expect("a terminal");
            assert_eq!(lflag(sub) & libc::ECHO, 0);
            assert_ne!(lflag(sub) & libc::ECHONL, 0);
            restore(&saved);
            assert_eq!(lflag(sub), before);
            // A file that is not a terminal is left alone.
            assert!(start(-1).is_none());
            // SAFETY: closes the two descriptors openpty made.
            unsafe {
                libc::close(sub);
                libc::close(main);
            }
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::sync::OnceLock;

    use windows_sys::{
        Win32::System::Console::{
            CONSOLE_MODE, ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE,
            SetConsoleCtrlHandler, SetConsoleMode,
        },
        core::BOOL,
    };

    pub type Saved = CONSOLE_MODE;

    /// What the Ctrl-C handler puts back: the first mode of this process.
    static FIRST: OnceLock<CONSOLE_MODE> = OnceLock::new();

    unsafe extern "system" fn on_ctrl(_kind: u32) -> BOOL {
        if let Some(mode) = FIRST.get() {
            // SAFETY: sets the console input mode read before.
            unsafe {
                SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), *mode);
            }
        }
        // Not handled: the default handler then ends the program.
        0
    }

    pub fn start_stdin() -> Option<Saved> {
        let mut mode: CONSOLE_MODE = 0;
        // SAFETY: plain console calls on this process's standard input.
        unsafe {
            let input = GetStdHandle(STD_INPUT_HANDLE);
            if GetConsoleMode(input, &mut mode) == 0 {
                return None;
            }
            let _ = FIRST.set(mode);
            SetConsoleCtrlHandler(Some(on_ctrl), 1);
            if SetConsoleMode(input, mode & !ENABLE_ECHO_INPUT) == 0 {
                SetConsoleCtrlHandler(Some(on_ctrl), 0);
                return None;
            }
        }
        Some(mode)
    }

    pub fn restore(mode: &Saved) {
        // SAFETY: puts back the console input mode read before.
        unsafe {
            SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), *mode);
            SetConsoleCtrlHandler(Some(on_ctrl), 0);
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    pub type Saved = ();

    pub fn start_stdin() -> Option<Saved> {
        None
    }

    pub fn restore(_: &Saved) {}
}
