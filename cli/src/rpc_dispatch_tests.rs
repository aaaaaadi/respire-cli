//! Wake delivery is checked against a long fallback, not a sub-10ms latency.
//! Thread-ready handshakes keep the watchdog separate from thread startup.
use super::*;

const FALLBACK: Duration = Duration::from_secs(60);
const WATCHDOG: Duration = Duration::from_secs(10);

fn receive_payload<T>(rx: &Receiver<T>) -> T {
    loop {
        match receive_dispatch_job(rx, FALLBACK) {
            Ok(value) => return value,
            Err(mpsc::RecvTimeoutError::Timeout) => continue, // park may wake spuriously
            Err(mpsc::RecvTimeoutError::Disconnected) => panic!("fixture sender disconnected"),
        }
    }
}

#[test]
fn completion_token_before_wait_is_not_lost() {
    let (ready, started) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let (_tx, rx) = mpsc::channel::<()>();
        ready.send(()).unwrap();
        std::thread::current().unpark();
        assert!(matches!(receive_dispatch_job(&rx, FALLBACK), Err(mpsc::RecvTimeoutError::Timeout)));
        done.send(()).unwrap();
    });
    started.recv_timeout(WATCHDOG).expect("receiver thread not ready");
    finished.recv_timeout(WATCHDOG).expect("completion unpark token was lost");
    thread.join().unwrap();
}

#[test]
fn request_arrival_wakes_wait_and_keeps_payload() {
    let (tx, rx) = mpsc::channel();
    let (ready, started) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        ready.send(std::thread::current()).unwrap();
        done.send(receive_payload(&rx)).unwrap();
    });
    let handle = started.recv_timeout(WATCHDOG).expect("receiver thread not ready");
    tx.send(37).unwrap();
    handle.unpark();
    assert_eq!(finished.recv_timeout(WATCHDOG).unwrap(), 37);
    thread.join().unwrap();
}

#[test]
fn shutdown_wake_does_not_fabricate_job() {
    let (_tx, rx) = mpsc::channel::<()>();
    let (ready, started) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        ready.send(std::thread::current()).unwrap();
        done.send(matches!(receive_dispatch_job(&rx, FALLBACK), Err(mpsc::RecvTimeoutError::Timeout))).unwrap();
    });
    started.recv_timeout(WATCHDOG).expect("receiver thread not ready").unpark();
    assert!(finished.recv_timeout(WATCHDOG).unwrap());
    thread.join().unwrap();
}

#[test]
fn channel_disconnect_keeps_terminal_semantics() {
    let (tx, rx) = mpsc::channel::<()>();
    drop(tx);
    assert!(matches!(receive_dispatch_job(&rx, FALLBACK), Err(mpsc::RecvTimeoutError::Disconnected)));
}

#[test]
fn job_queued_before_dispatcher_registration_needs_no_wake() {
    let (tx, rx) = mpsc::channel();
    tx.send(91).unwrap();
    let (ready, started) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        ready.send(()).unwrap();
        done.send(receive_payload(&rx)).unwrap();
    });
    started.recv_timeout(WATCHDOG).expect("receiver thread not ready");
    assert_eq!(finished.recv_timeout(WATCHDOG).unwrap(), 91);
    thread.join().unwrap();
}
