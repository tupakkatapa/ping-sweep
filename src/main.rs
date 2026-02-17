use clap::{Arg, Command};
use ipnetwork::{IpNetwork, Ipv4Network};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{HashMap, HashSet};
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const BATCH: usize = 64;
const MAX_TARGETS: usize = 1 << 16;

struct HostResult {
    ip: IpAddr,
    rtt_ns: u64,
    hostname: Option<String>,
    mac: Option<String>,
}

fn elapsed_nanos(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn record_rtt(data: &[u8], reply_type: u8, target_count: usize, rtt: &[AtomicU64], start: Instant) {
    if data.len() >= 8 && data[0] == reply_type {
        let seq = u16::from_be_bytes([data[6], data[7]]);
        let idx = usize::from(seq);
        if idx < target_count {
            rtt[idx].store(elapsed_nanos(start).max(1), Ordering::Relaxed);
        }
    }
}

fn main() {
    let args = cli().get_matches();

    let networks: Vec<IpNetwork> = match args.get_many::<IpNetwork>("subnet") {
        Some(nets) => nets.copied().collect(),
        None => match detect_subnet() {
            Ok(n) => vec![IpNetwork::V4(n)],
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        },
    };
    let json = args.get_flag("json");
    let show_rtt = args.get_flag("rtt");
    let resolve = args.get_flag("resolve");
    let show_mac = args.get_flag("mac");
    let timeout = Duration::from_millis(*args.get_one::<u64>("timeout").unwrap());

    let mut results = collect_results(&networks, timeout);

    if resolve {
        resolve_hostnames(&mut results);
    }
    if show_mac {
        let mac_table = read_mac_table();
        for r in &mut results {
            r.mac = mac_table.get(&r.ip).cloned();
        }
    }

    let any_alive = !results.is_empty();
    print_results(&results, json, show_rtt);

    if !any_alive {
        std::process::exit(1);
    }
}

fn collect_results(networks: &[IpNetwork], timeout: Duration) -> Vec<HostResult> {
    let mut results: Vec<HostResult> = Vec::new();

    for network in networks {
        match *network {
            IpNetwork::V4(net) => {
                if net.prefix() < 16 {
                    eprintln!(
                        "Error: subnet {net} too large (max /16, {MAX_TARGETS} hosts per sweep)"
                    );
                    std::process::exit(1);
                }
                let ips: Vec<Ipv4Addr> = net.iter().collect();
                let rtt_data = sweep_v4(&ips, timeout);
                for (i, &rtt_ns) in rtt_data.iter().enumerate() {
                    if rtt_ns > 0 {
                        results.push(HostResult {
                            ip: IpAddr::V4(ips[i]),
                            rtt_ns,
                            hostname: None,
                            mac: None,
                        });
                    }
                }
            }
            IpNetwork::V6(net) => {
                if net.prefix() < 112 {
                    eprintln!(
                        "Error: subnet {net} too large (max /112, {MAX_TARGETS} hosts per sweep)"
                    );
                    std::process::exit(1);
                }
                let ips: Vec<Ipv6Addr> = net.iter().collect();
                let rtt_data = sweep_v6(&ips, timeout);
                for (i, &rtt_ns) in rtt_data.iter().enumerate() {
                    if rtt_ns > 0 {
                        results.push(HostResult {
                            ip: IpAddr::V6(ips[i]),
                            rtt_ns,
                            hostname: None,
                            mac: None,
                        });
                    }
                }
            }
        }
    }

    let local = local_ips();
    results.retain(|r| !local.contains(&r.ip));
    results.sort_by(|a, b| a.ip.cmp(&b.ip));
    results.dedup_by_key(|r| r.ip);
    results
}

fn local_ips() -> HashSet<IpAddr> {
    let mut ips = HashSet::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) == 0 {
            let mut ifa = ifap;
            while !ifa.is_null() {
                let addr = (*ifa).ifa_addr;
                if !addr.is_null() {
                    match i32::from((*addr).sa_family) {
                        libc::AF_INET => {
                            let sa = std::ptr::read_unaligned(addr.cast::<libc::sockaddr_in>());
                            ips.insert(IpAddr::V4(Ipv4Addr::from(
                                sa.sin_addr.s_addr.to_ne_bytes(),
                            )));
                        }
                        libc::AF_INET6 => {
                            let sa = std::ptr::read_unaligned(addr.cast::<libc::sockaddr_in6>());
                            ips.insert(IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr)));
                        }
                        _ => {}
                    }
                }
                ifa = (*ifa).ifa_next;
            }
            libc::freeifaddrs(ifap);
        }
    }
    ips
}

fn print_results(results: &[HostResult], json: bool, show_rtt: bool) {
    if json {
        let entries: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                let mut obj = serde_json::Map::new();
                obj.insert("ip".into(), serde_json::Value::String(r.ip.to_string()));
                if let Some(ref h) = r.hostname {
                    obj.insert("hostname".into(), serde_json::Value::String(h.clone()));
                }
                if let Some(ref m) = r.mac {
                    obj.insert("mac".into(), serde_json::Value::String(m.clone()));
                }
                if show_rtt {
                    let micros = u32::try_from(r.rtt_ns / 1000).unwrap_or(u32::MAX);
                    let rtt_ms = (f64::from(micros) / 1000.0 * 100.0).round() / 100.0;
                    obj.insert("rtt_ms".into(), serde_json::json!(rtt_ms));
                }
                serde_json::Value::Object(obj)
            })
            .collect();
        println!("{}", serde_json::to_string(&entries).unwrap());
    } else {
        for r in results {
            let mut parts: Vec<String> = vec![r.ip.to_string()];
            if let Some(ref h) = r.hostname {
                parts.push(h.clone());
            }
            if let Some(ref m) = r.mac {
                parts.push(m.clone());
            }
            if show_rtt {
                let micros = r.rtt_ns / 1000;
                parts.push(format!("{}.{:02}ms", micros / 1000, (micros % 1000) / 10));
            }
            println!("{}", parts.join("\t"));
        }
    }
}

// --- IPv4 sweep ---

fn sweep_v4(ips: &[Ipv4Addr], timeout: Duration) -> Vec<u64> {
    if ips.is_empty() {
        return vec![];
    }

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).expect(
        "Failed to create ICMP socket. \
         Check that net.ipv4.ping_group_range includes your GID: \
         sysctl net.ipv4.ping_group_range",
    );

    let _ = sock.set_send_buffer_size(4 << 20);
    let _ = sock.set_recv_buffer_size(4 << 20);

    sock.set_nonblocking(true).expect("set_nonblocking");
    let fd = sock.as_raw_fd();

    let addrs: Vec<libc::sockaddr_in> = ips
        .iter()
        .map(|ip| libc::sockaddr_in {
            sin_family: libc::sa_family_t::try_from(libc::AF_INET).unwrap(),
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(ip.octets()),
            },
            sin_zero: [0; 8],
        })
        .collect();

    let packets: Vec<[u8; 8]> = (0..ips.len())
        .map(|i| build_echo_request(u16::try_from(i % (MAX_TARGETS)).unwrap()))
        .collect();

    let rtt_flags = Arc::new(
        (0..ips.len())
            .map(|_| AtomicU64::new(0))
            .collect::<Vec<_>>(),
    );

    let start = Instant::now();

    #[cfg(target_os = "linux")]
    let used_io_uring = try_io_uring(fd, &addrs, &packets, &rtt_flags, timeout, start);

    #[cfg(not(target_os = "linux"))]
    let used_io_uring = false;

    if !used_io_uring {
        let recv_flags = Arc::clone(&rtt_flags);
        let target_count = ips.len();

        let receiver = std::thread::spawn(move || {
            recv_loop(fd, &recv_flags, target_count, timeout, start);
        });

        send_all(fd, &addrs, &packets);

        let _ = receiver.join();
    }

    rtt_flags
        .iter()
        .map(|f| f.load(Ordering::Relaxed))
        .collect()
}

// --- IPv6 sweep ---

fn sweep_v6(ips: &[Ipv6Addr], timeout: Duration) -> Vec<u64> {
    if ips.is_empty() {
        return vec![];
    }

    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6)).expect(
        "Failed to create ICMPv6 socket. \
         Check that net.ipv4.ping_group_range includes your GID: \
         sysctl net.ipv4.ping_group_range",
    );

    let _ = sock.set_send_buffer_size(4 << 20);
    let _ = sock.set_recv_buffer_size(4 << 20);

    sock.set_nonblocking(true).expect("set_nonblocking");
    let fd = sock.as_raw_fd();

    let addrs: Vec<libc::sockaddr_in6> = ips
        .iter()
        .map(|ip| libc::sockaddr_in6 {
            sin6_family: libc::sa_family_t::try_from(libc::AF_INET6).unwrap(),
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: ip.octets(),
            },
            sin6_scope_id: 0,
        })
        .collect();

    let packets: Vec<[u8; 8]> = (0..ips.len())
        .map(|i| build_echo_request_v6(u16::try_from(i % (MAX_TARGETS)).unwrap()))
        .collect();

    let rtt_flags = Arc::new(
        (0..ips.len())
            .map(|_| AtomicU64::new(0))
            .collect::<Vec<_>>(),
    );

    let start = Instant::now();

    #[cfg(target_os = "linux")]
    let used_io_uring = try_io_uring_v6(fd, &addrs, &packets, &rtt_flags, timeout, start);

    #[cfg(not(target_os = "linux"))]
    let used_io_uring = false;

    if !used_io_uring {
        let recv_flags = Arc::clone(&rtt_flags);
        let target_count = ips.len();

        let receiver = std::thread::spawn(move || {
            recv_loop_v6(fd, &recv_flags, target_count, timeout, start);
        });

        send_all_v6(fd, &addrs, &packets);

        let _ = receiver.join();
    }

    rtt_flags
        .iter()
        .map(|f| f.load(Ordering::Relaxed))
        .collect()
}

// --- io_uring path (IPv4) ---

#[cfg(target_os = "linux")]
fn try_io_uring(
    fd: libc::c_int,
    addrs: &[libc::sockaddr_in],
    packets: &[[u8; 8]],
    rtt: &[AtomicU64],
    timeout: Duration,
    start: Instant,
) -> bool {
    use io_uring::{IoUring, opcode, types};
    const RECV_POOL: usize = 64;
    const RECV_BASE: u64 = 1 << 32;
    const TIMEOUT_TOKEN: u64 = u64::MAX;
    let Ok(mut ring) = IoUring::new(512) else {
        return false;
    };
    let target_count = addrs.len();
    let mut send_iovecs: Vec<libc::iovec> = packets
        .iter()
        .map(|pkt| libc::iovec {
            iov_base: pkt.as_ptr().cast_mut().cast(),
            iov_len: 8,
        })
        .collect();
    let mut send_msgs: Vec<libc::msghdr> = vec![unsafe { mem::zeroed() }; target_count];
    let send_iov_base = send_iovecs.as_mut_ptr();
    for (i, msg) in send_msgs.iter_mut().enumerate() {
        unsafe {
            msg.msg_name = addrs.as_ptr().add(i).cast_mut().cast();
            msg.msg_namelen = u32::try_from(mem::size_of::<libc::sockaddr_in>()).unwrap();
            msg.msg_iov = send_iov_base.add(i);
            msg.msg_iovlen = 1;
        }
    }
    let mut recv_bufs = [[0u8; 128]; RECV_POOL];
    let mut recv_iovecs: [libc::iovec; RECV_POOL] = unsafe { [mem::zeroed(); RECV_POOL] };
    let mut recv_addrs: [libc::sockaddr_in; RECV_POOL] = unsafe { [mem::zeroed(); RECV_POOL] };
    let mut recv_msgs: [libc::msghdr; RECV_POOL] = unsafe { [mem::zeroed(); RECV_POOL] };
    for (j, msg) in recv_msgs.iter_mut().enumerate() {
        recv_iovecs[j].iov_base = recv_bufs[j].as_mut_ptr().cast();
        recv_iovecs[j].iov_len = 128;
        msg.msg_name = std::ptr::addr_of_mut!(recv_addrs[j]).cast();
        msg.msg_namelen = u32::try_from(mem::size_of::<libc::sockaddr_in>()).unwrap();
        msg.msg_iov = std::ptr::addr_of_mut!(recv_iovecs[j]);
        msg.msg_iovlen = 1;
    }
    let (submitter, mut sq, mut cq) = ring.split();
    for (j, msg) in recv_msgs.iter_mut().enumerate() {
        let sqe = opcode::RecvMsg::new(types::Fd(fd), std::ptr::from_mut(msg))
            .build()
            .user_data(RECV_BASE | u64::try_from(j).unwrap());
        unsafe {
            let _ = sq.push(&sqe);
        }
    }
    let ts = types::Timespec::from(timeout);
    let timeout_sqe = opcode::Timeout::new(&ts).build().user_data(TIMEOUT_TOKEN);
    unsafe {
        let _ = sq.push(&timeout_sqe);
    }
    sq.sync();
    if submitter.submit().is_err() {
        return false;
    }
    let mut send_idx = 0;
    let mut done = false;
    while !done {
        while send_idx < target_count {
            let sqe = opcode::SendMsg::new(types::Fd(fd), std::ptr::addr_of!(send_msgs[send_idx]))
                .build()
                .user_data(u64::try_from(send_idx).unwrap());
            if unsafe { sq.push(&sqe) }.is_err() {
                break;
            }
            send_idx += 1;
        }
        sq.sync();
        match submitter.submit_and_wait(1) {
            Ok(_) => {}
            Err(ref e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(_) => break,
        }
        cq.sync();
        for cqe in &mut cq {
            let ud = cqe.user_data();
            if ud == TIMEOUT_TOKEN {
                done = true;
                break;
            }
            if ud >= RECV_BASE {
                let slot = usize::try_from(ud - RECV_BASE).unwrap();
                if cqe.result() > 0 {
                    let len = usize::try_from(cqe.result()).unwrap();
                    record_rtt(&recv_bufs[slot][..len], 0, target_count, rtt, start);
                }
                recv_bufs[slot] = [0u8; 128];
                let sqe =
                    opcode::RecvMsg::new(types::Fd(fd), std::ptr::addr_of_mut!(recv_msgs[slot]))
                        .build()
                        .user_data(RECV_BASE | u64::try_from(slot).unwrap());
                unsafe {
                    let _ = sq.push(&sqe);
                }
            }
        }
    }
    true
}

// --- io_uring path (IPv6) ---

#[cfg(target_os = "linux")]
fn try_io_uring_v6(
    fd: libc::c_int,
    addrs: &[libc::sockaddr_in6],
    packets: &[[u8; 8]],
    rtt: &[AtomicU64],
    timeout: Duration,
    start: Instant,
) -> bool {
    use io_uring::{IoUring, opcode, types};
    const RECV_POOL: usize = 64;
    const RECV_BASE: u64 = 1 << 32;
    const TIMEOUT_TOKEN: u64 = u64::MAX;
    let Ok(mut ring) = IoUring::new(512) else {
        return false;
    };
    let target_count = addrs.len();
    let mut send_iovecs: Vec<libc::iovec> = packets
        .iter()
        .map(|pkt| libc::iovec {
            iov_base: pkt.as_ptr().cast_mut().cast(),
            iov_len: 8,
        })
        .collect();
    let mut send_msgs: Vec<libc::msghdr> = vec![unsafe { mem::zeroed() }; target_count];
    let send_iov_base = send_iovecs.as_mut_ptr();
    for (i, msg) in send_msgs.iter_mut().enumerate() {
        unsafe {
            msg.msg_name = addrs.as_ptr().add(i).cast_mut().cast();
            msg.msg_namelen = u32::try_from(mem::size_of::<libc::sockaddr_in6>()).unwrap();
            msg.msg_iov = send_iov_base.add(i);
            msg.msg_iovlen = 1;
        }
    }
    let mut recv_bufs = [[0u8; 128]; RECV_POOL];
    let mut recv_iovecs: [libc::iovec; RECV_POOL] = unsafe { [mem::zeroed(); RECV_POOL] };
    let mut recv_addrs: [libc::sockaddr_in6; RECV_POOL] = unsafe { [mem::zeroed(); RECV_POOL] };
    let mut recv_msgs: [libc::msghdr; RECV_POOL] = unsafe { [mem::zeroed(); RECV_POOL] };
    for (j, msg) in recv_msgs.iter_mut().enumerate() {
        recv_iovecs[j].iov_base = recv_bufs[j].as_mut_ptr().cast();
        recv_iovecs[j].iov_len = 128;
        msg.msg_name = std::ptr::addr_of_mut!(recv_addrs[j]).cast();
        msg.msg_namelen = u32::try_from(mem::size_of::<libc::sockaddr_in6>()).unwrap();
        msg.msg_iov = std::ptr::addr_of_mut!(recv_iovecs[j]);
        msg.msg_iovlen = 1;
    }
    let (submitter, mut sq, mut cq) = ring.split();
    for (j, msg) in recv_msgs.iter_mut().enumerate() {
        let sqe = opcode::RecvMsg::new(types::Fd(fd), std::ptr::from_mut(msg))
            .build()
            .user_data(RECV_BASE | u64::try_from(j).unwrap());
        unsafe {
            let _ = sq.push(&sqe);
        }
    }
    let ts = types::Timespec::from(timeout);
    let timeout_sqe = opcode::Timeout::new(&ts).build().user_data(TIMEOUT_TOKEN);
    unsafe {
        let _ = sq.push(&timeout_sqe);
    }
    sq.sync();
    if submitter.submit().is_err() {
        return false;
    }
    let mut send_idx = 0;
    let mut done = false;
    while !done {
        while send_idx < target_count {
            let sqe = opcode::SendMsg::new(types::Fd(fd), std::ptr::addr_of!(send_msgs[send_idx]))
                .build()
                .user_data(u64::try_from(send_idx).unwrap());
            if unsafe { sq.push(&sqe) }.is_err() {
                break;
            }
            send_idx += 1;
        }
        sq.sync();
        match submitter.submit_and_wait(1) {
            Ok(_) => {}
            Err(ref e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            Err(_) => break,
        }
        cq.sync();
        for cqe in &mut cq {
            let ud = cqe.user_data();
            if ud == TIMEOUT_TOKEN {
                done = true;
                break;
            }
            if ud >= RECV_BASE {
                let slot = usize::try_from(ud - RECV_BASE).unwrap();
                if cqe.result() > 0 {
                    let len = usize::try_from(cqe.result()).unwrap();
                    record_rtt(&recv_bufs[slot][..len], 129, target_count, rtt, start);
                }
                recv_bufs[slot] = [0u8; 128];
                let sqe =
                    opcode::RecvMsg::new(types::Fd(fd), std::ptr::addr_of_mut!(recv_msgs[slot]))
                        .build()
                        .user_data(RECV_BASE | u64::try_from(slot).unwrap());
                unsafe {
                    let _ = sq.push(&sqe);
                }
            }
        }
    }
    true
}

// --- Packet construction ---

#[cfg(target_os = "linux")]
fn build_echo_request(seq: u16) -> [u8; 8] {
    let mut pkt = [0u8; 8];
    pkt[0] = 8;
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    pkt
}

#[cfg(not(target_os = "linux"))]
fn build_echo_request(seq: u16) -> [u8; 8] {
    let mut pkt = [0u8; 8];
    pkt[0] = 8;
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    let checksum = internet_checksum(&pkt);
    pkt[2..4].copy_from_slice(&checksum.to_be_bytes());
    pkt
}

fn build_echo_request_v6(seq: u16) -> [u8; 8] {
    let mut pkt = [0u8; 8];
    pkt[0] = 128;
    pkt[6..8].copy_from_slice(&seq.to_be_bytes());
    pkt
}

#[cfg(not(target_os = "linux"))]
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap()
}

// --- Error classification ---

enum SendOutcome {
    Retriable,
    Unreachable,
    Fatal,
}

fn classify_send_error(err: &io::Error) -> SendOutcome {
    match err.raw_os_error() {
        Some(libc::EAGAIN | libc::ENOBUFS) => SendOutcome::Retriable,
        Some(libc::ENETUNREACH | libc::EHOSTUNREACH | libc::ECONNREFUSED) => {
            SendOutcome::Unreachable
        }
        Some(libc::EPERM) => SendOutcome::Fatal,
        _ => SendOutcome::Unreachable,
    }
}

// --- Send (IPv4) ---

#[cfg(target_os = "linux")]
fn send_all(fd: libc::c_int, addrs: &[libc::sockaddr_in], packets: &[[u8; 8]]) {
    let mut i = 0;
    while i < addrs.len() {
        let batch_end = (i + BATCH).min(addrs.len());
        let count = batch_end - i;

        unsafe {
            let mut iovecs = [mem::zeroed::<libc::iovec>(); BATCH];
            let mut msgs = [mem::zeroed::<libc::mmsghdr>(); BATCH];

            for j in 0..count {
                iovecs[j].iov_base = packets[i + j].as_ptr().cast_mut().cast();
                iovecs[j].iov_len = 8;
                msgs[j].msg_hdr.msg_name = std::ptr::addr_of!(addrs[i + j]).cast_mut().cast();
                msgs[j].msg_hdr.msg_namelen =
                    u32::try_from(mem::size_of::<libc::sockaddr_in>()).unwrap();
                msgs[j].msg_hdr.msg_iov = std::ptr::addr_of_mut!(iovecs[j]);
                msgs[j].msg_hdr.msg_iovlen = 1;
            }

            let mut sent = 0;
            while sent < count {
                let n = libc::sendmmsg(
                    fd,
                    msgs[sent..].as_mut_ptr(),
                    u32::try_from(count - sent).unwrap(),
                    0,
                );
                if n < 0 {
                    let err = io::Error::last_os_error();
                    match classify_send_error(&err) {
                        SendOutcome::Retriable => {
                            std::thread::sleep(Duration::from_micros(100));
                        }
                        SendOutcome::Fatal => {
                            eprintln!("Fatal send error: {err}");
                            std::process::exit(1);
                        }
                        SendOutcome::Unreachable => {
                            sent += 1;
                        }
                    }
                } else {
                    sent += usize::try_from(n).unwrap();
                }
            }
        }

        i = batch_end;
    }
}

#[cfg(not(target_os = "linux"))]
fn send_all(fd: libc::c_int, addrs: &[libc::sockaddr_in], packets: &[[u8; 8]]) {
    for (addr, packet) in addrs.iter().zip(packets.iter()) {
        loop {
            let sendto_rc = unsafe {
                libc::sendto(
                    fd,
                    packet.as_ptr().cast(),
                    8,
                    0,
                    std::ptr::from_ref(addr).cast(),
                    u32::try_from(mem::size_of::<libc::sockaddr_in>()).unwrap(),
                )
            };
            if sendto_rc >= 0 {
                break;
            }
            let err = io::Error::last_os_error();
            match classify_send_error(&err) {
                SendOutcome::Retriable => {
                    std::thread::sleep(Duration::from_micros(100));
                }
                SendOutcome::Fatal => {
                    eprintln!("Fatal send error: {err}");
                    std::process::exit(1);
                }
                SendOutcome::Unreachable => break,
            }
        }
    }
}

// --- Send (IPv6) ---

#[cfg(target_os = "linux")]
fn send_all_v6(fd: libc::c_int, addrs: &[libc::sockaddr_in6], packets: &[[u8; 8]]) {
    let mut i = 0;
    while i < addrs.len() {
        let batch_end = (i + BATCH).min(addrs.len());
        let count = batch_end - i;

        unsafe {
            let mut iovecs = [mem::zeroed::<libc::iovec>(); BATCH];
            let mut msgs = [mem::zeroed::<libc::mmsghdr>(); BATCH];

            for j in 0..count {
                iovecs[j].iov_base = packets[i + j].as_ptr().cast_mut().cast();
                iovecs[j].iov_len = 8;
                msgs[j].msg_hdr.msg_name = std::ptr::addr_of!(addrs[i + j]).cast_mut().cast();
                msgs[j].msg_hdr.msg_namelen =
                    u32::try_from(mem::size_of::<libc::sockaddr_in6>()).unwrap();
                msgs[j].msg_hdr.msg_iov = std::ptr::addr_of_mut!(iovecs[j]);
                msgs[j].msg_hdr.msg_iovlen = 1;
            }

            let mut sent = 0;
            while sent < count {
                let n = libc::sendmmsg(
                    fd,
                    msgs[sent..].as_mut_ptr(),
                    u32::try_from(count - sent).unwrap(),
                    0,
                );
                if n < 0 {
                    let err = io::Error::last_os_error();
                    match classify_send_error(&err) {
                        SendOutcome::Retriable => {
                            std::thread::sleep(Duration::from_micros(100));
                        }
                        SendOutcome::Fatal => {
                            eprintln!("Fatal send error: {err}");
                            std::process::exit(1);
                        }
                        SendOutcome::Unreachable => {
                            sent += 1;
                        }
                    }
                } else {
                    sent += usize::try_from(n).unwrap();
                }
            }
        }

        i = batch_end;
    }
}

#[cfg(not(target_os = "linux"))]
fn send_all_v6(fd: libc::c_int, addrs: &[libc::sockaddr_in6], packets: &[[u8; 8]]) {
    for (addr, packet) in addrs.iter().zip(packets.iter()) {
        loop {
            let sendto_rc = unsafe {
                libc::sendto(
                    fd,
                    packet.as_ptr().cast(),
                    8,
                    0,
                    std::ptr::from_ref(addr).cast(),
                    u32::try_from(mem::size_of::<libc::sockaddr_in6>()).unwrap(),
                )
            };
            if sendto_rc >= 0 {
                break;
            }
            let err = io::Error::last_os_error();
            match classify_send_error(&err) {
                SendOutcome::Retriable => {
                    std::thread::sleep(Duration::from_micros(100));
                }
                SendOutcome::Fatal => {
                    eprintln!("Fatal send error: {err}");
                    std::process::exit(1);
                }
                SendOutcome::Unreachable => break,
            }
        }
    }
}

// --- Poll helper ---

fn poll_fd(fd: libc::c_int, remaining: Duration) -> i32 {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout_ms = i32::try_from(remaining.as_millis().min(2_147_483_647)).unwrap();
    unsafe { libc::poll(std::ptr::addr_of_mut!(pfd), 1, timeout_ms) }
}

// --- Receive (IPv4) ---

#[cfg(target_os = "linux")]
fn recv_loop(
    fd: libc::c_int,
    rtt: &[AtomicU64],
    target_count: usize,
    timeout: Duration,
    start: Instant,
) {
    let deadline = Instant::now() + timeout;

    let mut bufs = [[0u8; 128]; BATCH];
    let mut iovecs = unsafe { [mem::zeroed::<libc::iovec>(); BATCH] };
    let mut addrs = unsafe { [mem::zeroed::<libc::sockaddr_in>(); BATCH] };
    let mut msgs = unsafe { [mem::zeroed::<libc::mmsghdr>(); BATCH] };

    for j in 0..BATCH {
        iovecs[j].iov_base = bufs[j].as_mut_ptr().cast();
        iovecs[j].iov_len = 128;
        msgs[j].msg_hdr.msg_name = std::ptr::addr_of_mut!(addrs[j]).cast();
        msgs[j].msg_hdr.msg_namelen = u32::try_from(mem::size_of::<libc::sockaddr_in>()).unwrap();
        msgs[j].msg_hdr.msg_iov = std::ptr::addr_of_mut!(iovecs[j]);
        msgs[j].msg_hdr.msg_iovlen = 1;
    }

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let poll_rc = poll_fd(fd, remaining);
        if poll_rc <= 0 {
            if poll_rc == 0 {
                break;
            }
            continue;
        }

        let n = unsafe {
            libc::recvmmsg(
                fd,
                msgs.as_mut_ptr(),
                u32::try_from(BATCH).unwrap(),
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };
        if n > 0 {
            for k in 0..usize::try_from(n).unwrap() {
                let len = usize::try_from(msgs[k].msg_len).unwrap();
                record_rtt(&bufs[k][..len], 0, target_count, rtt, start);
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn recv_loop(
    fd: libc::c_int,
    rtt: &[AtomicU64],
    target_count: usize,
    timeout: Duration,
    start: Instant,
) {
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 256];

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let poll_rc = poll_fd(fd, remaining);
        if poll_rc <= 0 {
            if poll_rc == 0 {
                break;
            }
            continue;
        }

        let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
        let mut addrlen = u32::try_from(mem::size_of::<libc::sockaddr_in>()).unwrap();
        let n = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_DONTWAIT,
                std::ptr::addr_of_mut!(addr).cast(),
                std::ptr::addr_of_mut!(addrlen),
            )
        };
        if n < 0 {
            continue;
        }
        let nbytes = usize::try_from(n).unwrap();
        if nbytes < 28 {
            continue;
        }
        let ihl = usize::from(buf[0] & 0x0F) * 4;
        if nbytes >= ihl + 8 {
            record_rtt(&buf[ihl..nbytes], 0, target_count, rtt, start);
        }
    }
}

// --- Receive (IPv6) ---

#[cfg(target_os = "linux")]
fn recv_loop_v6(
    fd: libc::c_int,
    rtt: &[AtomicU64],
    target_count: usize,
    timeout: Duration,
    start: Instant,
) {
    let deadline = Instant::now() + timeout;

    let mut bufs = [[0u8; 128]; BATCH];
    let mut iovecs = unsafe { [mem::zeroed::<libc::iovec>(); BATCH] };
    let mut addrs = unsafe { [mem::zeroed::<libc::sockaddr_in6>(); BATCH] };
    let mut msgs = unsafe { [mem::zeroed::<libc::mmsghdr>(); BATCH] };

    for j in 0..BATCH {
        iovecs[j].iov_base = bufs[j].as_mut_ptr().cast();
        iovecs[j].iov_len = 128;
        msgs[j].msg_hdr.msg_name = std::ptr::addr_of_mut!(addrs[j]).cast();
        msgs[j].msg_hdr.msg_namelen = u32::try_from(mem::size_of::<libc::sockaddr_in6>()).unwrap();
        msgs[j].msg_hdr.msg_iov = std::ptr::addr_of_mut!(iovecs[j]);
        msgs[j].msg_hdr.msg_iovlen = 1;
    }

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let poll_rc = poll_fd(fd, remaining);
        if poll_rc <= 0 {
            if poll_rc == 0 {
                break;
            }
            continue;
        }

        let n = unsafe {
            libc::recvmmsg(
                fd,
                msgs.as_mut_ptr(),
                u32::try_from(BATCH).unwrap(),
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };
        if n > 0 {
            for k in 0..usize::try_from(n).unwrap() {
                let len = usize::try_from(msgs[k].msg_len).unwrap();
                record_rtt(&bufs[k][..len], 129, target_count, rtt, start);
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn recv_loop_v6(
    fd: libc::c_int,
    rtt: &[AtomicU64],
    target_count: usize,
    timeout: Duration,
    start: Instant,
) {
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 256];

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let poll_rc = poll_fd(fd, remaining);
        if poll_rc <= 0 {
            if poll_rc == 0 {
                break;
            }
            continue;
        }

        let mut addr: libc::sockaddr_in6 = unsafe { mem::zeroed() };
        let mut addrlen = u32::try_from(mem::size_of::<libc::sockaddr_in6>()).unwrap();
        let n = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_DONTWAIT,
                std::ptr::addr_of_mut!(addr).cast(),
                std::ptr::addr_of_mut!(addrlen),
            )
        };
        if n < 0 {
            continue;
        }
        let nbytes = usize::try_from(n).unwrap();
        record_rtt(&buf[..nbytes], 129, target_count, rtt, start);
    }
}

// --- Reverse DNS ---

fn resolve_hostname(addr: &IpAddr) -> Option<String> {
    let mut host = [0u8; 1025];
    let gni_rc = unsafe {
        match addr {
            IpAddr::V4(v4) => {
                let sa = libc::sockaddr_in {
                    sin_family: libc::sa_family_t::try_from(libc::AF_INET).unwrap(),
                    sin_port: 0,
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.octets()),
                    },
                    sin_zero: [0; 8],
                };
                libc::getnameinfo(
                    std::ptr::from_ref(&sa).cast(),
                    u32::try_from(mem::size_of::<libc::sockaddr_in>()).unwrap(),
                    host.as_mut_ptr().cast(),
                    u32::try_from(host.len()).unwrap(),
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
            IpAddr::V6(v6) => {
                let sa = libc::sockaddr_in6 {
                    sin6_family: libc::sa_family_t::try_from(libc::AF_INET6).unwrap(),
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr {
                        s6_addr: v6.octets(),
                    },
                    sin6_scope_id: 0,
                };
                libc::getnameinfo(
                    std::ptr::from_ref(&sa).cast(),
                    u32::try_from(mem::size_of::<libc::sockaddr_in6>()).unwrap(),
                    host.as_mut_ptr().cast(),
                    u32::try_from(host.len()).unwrap(),
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };

    if gni_rc != 0 {
        return None;
    }

    let hostname = unsafe { std::ffi::CStr::from_ptr(host.as_ptr().cast()) }
        .to_string_lossy()
        .into_owned();
    Some(hostname)
}

fn resolve_hostnames(results: &mut [HostResult]) {
    let handles: Vec<_> = results
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let ip = r.ip;
            std::thread::spawn(move || (i, resolve_hostname(&ip)))
        })
        .collect();

    for handle in handles {
        if let Ok((i, hostname)) = handle.join() {
            results[i].hostname = hostname;
        }
    }
}

// --- MAC address (ARP table) ---

fn read_mac_table() -> HashMap<IpAddr, String> {
    let mut table = HashMap::new();
    if let Ok(contents) = std::fs::read_to_string("/proc/net/arp") {
        for line in contents.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 && parts[3] != "00:00:00:00:00:00" {
                if let Ok(ip) = parts[0].parse::<IpAddr>() {
                    table.insert(ip, parts[3].to_string());
                }
            }
        }
    }
    table
}

// --- CLI ---

fn cli() -> Command {
    Command::new("ping-sweep")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Tupakkatapa")
        .about("Performs a ping sweep on a given subnet")
        .arg(
            Arg::new("subnet")
                .short('s')
                .long("subnet")
                .value_name("SUBNET")
                .help("Subnet in CIDR notation, IPv4 or IPv6 (auto-detected if omitted)")
                .action(clap::ArgAction::Append)
                .value_parser(clap::value_parser!(IpNetwork)),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .value_name("MS")
                .help("Ping timeout in milliseconds")
                .default_value("200")
                .value_parser(clap::value_parser!(u64)),
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .help("Output results as a JSON array")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("rtt")
                .short('R')
                .long("rtt")
                .help("Show round-trip time for each host")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("resolve")
                .short('r')
                .long("resolve")
                .help("Resolve hostnames via reverse DNS")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("mac")
                .short('m')
                .long("mac")
                .help("Show MAC addresses from ARP table")
                .action(clap::ArgAction::SetTrue),
        )
}

fn detect_subnet() -> Result<Ipv4Network, String> {
    let route_data = std::fs::read_to_string("/proc/net/route")
        .map_err(|e| format!("Failed to read /proc/net/route: {e}"))?;

    let iface = route_data
        .lines()
        .skip(1)
        .find_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 8 && parts[1] == "00000000" && parts[7] == "00000000" {
                Some(parts[0].to_string())
            } else {
                None
            }
        })
        .ok_or("No default route found")?;

    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return Err("getifaddrs failed".into());
        }
        let result = find_iface_subnet(ifap, &iface);
        libc::freeifaddrs(ifap);
        result
    }
}

unsafe fn find_iface_subnet(
    mut ifa: *mut libc::ifaddrs,
    iface: &str,
) -> Result<Ipv4Network, String> {
    while !ifa.is_null() {
        let name = std::ffi::CStr::from_ptr((*ifa).ifa_name).to_string_lossy();
        let addr = (*ifa).ifa_addr;
        let mask = (*ifa).ifa_netmask;
        if name == iface
            && !addr.is_null()
            && !mask.is_null()
            && i32::from((*addr).sa_family) == libc::AF_INET
        {
            let sa = std::ptr::read_unaligned(addr.cast::<libc::sockaddr_in>());
            let sm = std::ptr::read_unaligned(mask.cast::<libc::sockaddr_in>());
            let ip = Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes());
            let prefix =
                u8::try_from(u32::from_be(sm.sin_addr.s_addr).leading_ones()).unwrap_or(32);
            return Ipv4Network::new(ip, prefix)
                .map_err(|e| format!("Failed to create network: {e}"));
        }
        ifa = (*ifa).ifa_next;
    }
    Err("No IPv4 address found on default interface".into())
}
