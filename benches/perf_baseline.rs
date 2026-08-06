use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use shoes::address::{Address, NetLocation};
use shoes::anytls::build_open_destination_frames_for_bench;
use shoes::http_handler::{
    build_http_forward_initial_data_for_bench, classify_http_proxy_header_line,
    parse_http_forward_url,
};
use shoes::socks_handler::{
    read_location_direct, socks_location_len, try_write_location_to_buf, try_write_location_to_vec,
};
use shoes::v2board::outbound::index::CompiledRules;
use shoes::v2board::outbound::rules::{ParsedRule, parse_crs_line};

#[global_allocator]
static ALLOC: CountingAllocator = CountingAllocator;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static DEALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        ALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[derive(Clone, Copy)]
struct AllocSnapshot {
    allocations: u64,
    deallocations: u64,
    allocated_bytes: u64,
}

impl AllocSnapshot {
    fn take() -> Self {
        Self {
            allocations: ALLOCATIONS.load(Ordering::Relaxed),
            deallocations: DEALLOCATIONS.load(Ordering::Relaxed),
            allocated_bytes: ALLOCATED_BYTES.load(Ordering::Relaxed),
        }
    }

    fn delta(self, after: Self) -> Self {
        Self {
            allocations: after.allocations - self.allocations,
            deallocations: after.deallocations - self.deallocations,
            allocated_bytes: after.allocated_bytes - self.allocated_bytes,
        }
    }
}

#[derive(Clone, Copy)]
struct UsageSnapshot {
    user_us: i64,
    sys_us: i64,
    max_rss_kb: i64,
}

impl UsageSnapshot {
    fn take() -> Self {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        if rc != 0 {
            return Self {
                user_us: 0,
                sys_us: 0,
                max_rss_kb: 0,
            };
        }
        let usage = unsafe { usage.assume_init() };
        Self {
            user_us: timeval_us(usage.ru_utime),
            sys_us: timeval_us(usage.ru_stime),
            max_rss_kb: usage.ru_maxrss,
        }
    }

    fn cpu_delta_us(self, after: Self) -> i64 {
        (after.user_us - self.user_us) + (after.sys_us - self.sys_us)
    }
}

fn timeval_us(time: libc::timeval) -> i64 {
    time.tv_sec.saturating_mul(1_000_000) + time.tv_usec
}

struct Metric {
    name: &'static str,
    iterations: u64,
    elapsed: Duration,
    cpu_us: i64,
    max_rss_kb: i64,
    allocs: AllocSnapshot,
}

impl Metric {
    fn print(&self) {
        let elapsed_ns = self.elapsed.as_nanos() as f64;
        let iterations = self.iterations as f64;
        let secs = self.elapsed.as_secs_f64();
        println!(
            "{{\"name\":\"{}\",\"iterations\":{},\"elapsed_ms\":{:.3},\"ns_per_op\":{:.2},\"ops_per_sec\":{:.2},\"cpu_us\":{},\"max_rss_kb\":{},\"allocs_per_op\":{:.4},\"bytes_per_op\":{:.2}}}",
            self.name,
            self.iterations,
            secs * 1000.0,
            elapsed_ns / iterations,
            iterations / secs,
            self.cpu_us,
            self.max_rss_kb,
            self.allocs.allocations as f64 / iterations,
            self.allocs.allocated_bytes as f64 / iterations,
        );
    }
}

fn measure(name: &'static str, iterations: u64, mut f: impl FnMut(u64)) -> Metric {
    for i in 0..10_000 {
        f(black_box(i));
    }
    let alloc_before = AllocSnapshot::take();
    let usage_before = UsageSnapshot::take();
    let started = Instant::now();
    for i in 0..iterations {
        f(black_box(i));
    }
    let elapsed = started.elapsed();
    let usage_after = UsageSnapshot::take();
    let allocs = alloc_before.delta(AllocSnapshot::take());
    Metric {
        name,
        iterations,
        elapsed,
        cpu_us: usage_before.cpu_delta_us(usage_after),
        max_rss_kb: usage_after.max_rss_kb,
        allocs,
    }
}

fn parse(line: String) -> ParsedRule {
    parse_crs_line(&line, 1, "bench")
        .expect("rule parsed")
        .expect("rule exists")
}

fn routing_rules() -> CompiledRules {
    let mut rules = Vec::new();
    for i in 0..1_000 {
        rules.push(parse(format!("DOMAIN-SUFFIX,svc{i}.example.com,out-a")));
        rules.push(parse(format!("DOMAIN,api{i}.example.net,out-b")));
    }
    for i in 0..256 {
        rules.push(parse(format!("DOMAIN-KEYWORD,keyword{i},out-c")));
        rules.push(parse(format!("IP-CIDR,10.{i}.0.0/16,out-d")));
    }
    for i in 0..128 {
        rules.push(parse(format!("IP-CIDR6,2001:db8:{i:x}::/48,out-e")));
    }
    rules.push(parse("MATCH,direct".to_string()));
    CompiledRules::compile(rules, |_| Ok(Vec::new()), |_| Ok(Vec::new())).expect("rules compile")
}

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio runtime builds");
    let rules = routing_rules();
    let lowercase_domains = [
        "api17.example.net",
        "www.svc42.example.com",
        "cdn.keyword77.invalid",
        "nomatch.example.org",
    ];
    let mixedcase_domains = [
        "Api17.Example.Net",
        "WWW.Svc42.Example.Com",
        "Cdn.Keyword77.Invalid",
        "NoMatch.Example.Org",
    ];
    let ipv4 = [
        IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
        IpAddr::V4(Ipv4Addr::new(10, 200, 2, 3)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
    ];
    let ipv6 = [
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x20, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x7f, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];

    measure("routing.match_domain.lowercase", 1_000_000, |i| {
        let domain = lowercase_domains[i as usize % lowercase_domains.len()];
        black_box(rules.match_domain(black_box(domain)));
    })
    .print();

    measure("routing.match_domain.mixedcase", 1_000_000, |i| {
        let domain = mixedcase_domains[i as usize % mixedcase_domains.len()];
        black_box(rules.match_domain(black_box(domain)));
    })
    .print();

    measure("routing.match_ip.ipv4", 1_000_000, |i| {
        let ip = ipv4[i as usize % ipv4.len()];
        black_box(rules.match_ip(black_box(ip), black_box(443)));
    })
    .print();

    measure("routing.match_ip.ipv6", 1_000_000, |i| {
        let ip = ipv6[i as usize % ipv6.len()];
        black_box(rules.match_ip(black_box(ip), black_box(443)));
    })
    .print();

    let forward_urls = [
        "http://127.0.0.1:19209/payload.bin",
        "http://example.com:8080/path/to/resource?query=1",
        "http://[::1]:19209/payload.bin",
        "http://proxy-bench.example.test/",
    ];
    measure("http.parse_forward_url", 1_000_000, |i| {
        let url = forward_urls[i as usize % forward_urls.len()];
        black_box(parse_http_forward_url(black_box(url)).expect("HTTP forward URL parses"));
    })
    .print();

    let header_lines = [
        "Host: 127.0.0.1:19209",
        "User-Agent: shoes-basic-proxy-perf-client/1",
        "Accept: */*",
        "Proxy-Authorization: Basic c2hvZXM6c2hvZXM=",
        "Connection: keep-alive",
        "Proxy-Connection: keep-alive",
    ];
    measure("http.classify_proxy_header", 1_000_000, |i| {
        let line = header_lines[i as usize % header_lines.len()];
        black_box(classify_http_proxy_header_line(black_box(line)));
    })
    .print();

    let forward_headers = [
        "Host: example-bench.test",
        "User-Agent: shoes-basic-proxy-perf-client/1",
        "Accept: */*",
        "X-Bench-Request: 0123456789abcdef",
    ];
    let buffered_body = b"bench-body-prefix";
    measure("http.build_forward_initial_data", 1_000_000, |_| {
        black_box(
            build_http_forward_initial_data_for_bench(
                black_box("GET"),
                black_box("/payload.bin?size=1048576"),
                black_box("HTTP/1.1"),
                black_box(&forward_headers),
                black_box(buffered_body),
            )
            .expect("HTTP forward initial data builds"),
        );
    })
    .print();

    let socks_ipv4 = [0x01, 127, 0, 0, 1, 0x01, 0xbb];
    let socks_ipv6 = [
        0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xbb,
    ];
    let socks_domain = [
        0x03, 0x12, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'-', b'b', b'e', b'n', b'c', b'h',
        b'.', b't', b'e', b's', b't', 0x01, 0xbb,
    ];
    measure("socks.read_location_direct.ipv4", 1_000_000, |_| {
        let mut input = black_box(&socks_ipv4[..]);
        black_box(
            rt.block_on(read_location_direct(&mut input))
                .expect("SOCKS IPv4 parses"),
        );
    })
    .print();
    measure("socks.read_location_direct.ipv6", 1_000_000, |_| {
        let mut input = black_box(&socks_ipv6[..]);
        black_box(
            rt.block_on(read_location_direct(&mut input))
                .expect("SOCKS IPv6 parses"),
        );
    })
    .print();
    measure("socks.read_location_direct.domain", 1_000_000, |_| {
        let mut input = black_box(&socks_domain[..]);
        black_box(
            rt.block_on(read_location_direct(&mut input))
                .expect("SOCKS domain parses"),
        );
    })
    .print();

    let write_ipv4 = NetLocation::new(Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 443);
    let write_ipv6 = NetLocation::new(Address::Ipv6(Ipv6Addr::LOCALHOST), 443);
    let write_domain = NetLocation::new(Address::Hostname("example-bench.test".to_string()), 443);
    measure("socks.write_location_to_vec.ipv4", 1_000_000, |_| {
        black_box(try_write_location_to_vec(black_box(&write_ipv4)).expect("SOCKS IPv4 encodes"));
    })
    .print();
    measure("socks.write_location_to_vec.ipv6", 1_000_000, |_| {
        black_box(try_write_location_to_vec(black_box(&write_ipv6)).expect("SOCKS IPv6 encodes"));
    })
    .print();
    measure("socks.write_location_to_vec.domain", 1_000_000, |_| {
        black_box(
            try_write_location_to_vec(black_box(&write_domain)).expect("SOCKS domain encodes"),
        );
    })
    .print();

    let mut write_ipv4_buf = Vec::with_capacity(socks_location_len(&write_ipv4).unwrap());
    measure("socks.write_location_to_buf.ipv4", 1_000_000, |_| {
        write_ipv4_buf.clear();
        try_write_location_to_buf(black_box(&write_ipv4), &mut write_ipv4_buf)
            .expect("SOCKS IPv4 encodes");
        black_box(&write_ipv4_buf);
    })
    .print();
    let mut write_ipv6_buf = Vec::with_capacity(socks_location_len(&write_ipv6).unwrap());
    measure("socks.write_location_to_buf.ipv6", 1_000_000, |_| {
        write_ipv6_buf.clear();
        try_write_location_to_buf(black_box(&write_ipv6), &mut write_ipv6_buf)
            .expect("SOCKS IPv6 encodes");
        black_box(&write_ipv6_buf);
    })
    .print();
    let mut write_domain_buf = Vec::with_capacity(socks_location_len(&write_domain).unwrap());
    measure("socks.write_location_to_buf.domain", 1_000_000, |_| {
        write_domain_buf.clear();
        try_write_location_to_buf(black_box(&write_domain), &mut write_domain_buf)
            .expect("SOCKS domain encodes");
        black_box(&write_domain_buf);
    })
    .print();

    measure(
        "anytls.build_open_destination_frames.first",
        1_000_000,
        |_| {
            black_box(
                build_open_destination_frames_for_bench(black_box(&write_domain))
                    .expect("AnyTLS first stream frames encode"),
            );
        },
    )
    .print();
    measure(
        "anytls.build_open_destination_frames.subsequent",
        1_000_000,
        |_| {
            black_box(
                build_open_destination_frames_for_bench(black_box(&write_domain))
                    .expect("AnyTLS subsequent stream frames encode"),
            );
        },
    )
    .print();
}
