fn main() {
    let mut cap = pcap::Capture::from_device(pcap::Device::lookup().unwrap())
        .unwrap()
        .timeout(1000)
        .open()
        .unwrap();

    // filter out all packets that don't have 127.0.0.1 as a source or destination.
    let filter = cap.compile_filter("host 127.0.0.1", true).unwrap();
    cap.filter(&filter).unwrap();

    // statistics!
    let mut cap = cap.stats_mode().unwrap();

    for packet in cap.iter().take(8) {
        println!("got packet! {:?}", packet.unwrap());
    }
    pcap::pcap_loop(cap, Some(8), handler).unwrap();
}

fn handler(packet: pcap::Packet) {
    println!("Loop Got {:?}", packet)
}
