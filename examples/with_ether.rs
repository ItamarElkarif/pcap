fn main() {
    // listen on the device named "any", which is only available on Linux. This is only for
    // demonstration purposes.
    let mut cap = pcap::Capture::from_device("any")
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    let mut filter = cap.compile_filter("ip", true).unwrap();
    cap.filter(&mut filter).unwrap();

    for packet in cap.iter().parse_ethernet().take(8) {
        println!("got packet! {:?}", packet);
    }
    pcap::pcap_loop(cap, Some(8), handler).unwrap();
}

fn handler(packet: pcap::Packet) {
    println!("Loop Got {:?}", packet)
}
