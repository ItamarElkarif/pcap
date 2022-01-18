use crate::Activated;
use crate::Error;
use crate::Packet;
use crate::State;
use crate::{raw, Capture, PacketHeader};
use libc::c_int;
use libc::c_uchar;

/// The type for the function to pass into pcap_loop
pub type HandlerFunc = fn(Packet) -> ();

/// An internal function to convert the callback capture into rust safe function,
/// #Safety
/// using mem::transmute here is fine since `HandlerFunc` **Should** be the equivalent of
/// pcap_handler (removing the extern and unsafe keyword, need to check if removing them have
/// unidentified behavior although we are converting from and into the same type)
unsafe extern "C" fn capturer(
    params: *mut c_uchar,
    raw_header: *const raw::pcap_pkthdr,
    raw_pkt_data: *const c_uchar,
) {
    let callback: HandlerFunc = std::mem::transmute(params);
    let header = *(raw_header as *const PacketHeader);
    // let header = &*(&*raw_header as *const raw::pcap_pkthdr as *const PacketHeader);
    let pkt_data = std::slice::from_raw_parts(raw_pkt_data, header.caplen as _);

    callback(Packet::new(&header, pkt_data));
}

///Processes packets from a live capture or ``savefile`` until max packets are processed,
///or the end of the ``savefile`` is reached when reading from a ``savefile``
/// **Note:** pcap_loop is blocking so `setnonblock` will have no effect
pub fn pcap_loop<T: State>(
    capture: Capture<T>,
    max: Option<usize>,
    handler: HandlerFunc,
) -> Result<(), Error> {
    let result = unsafe {
        raw::pcap_loop(
            *capture.handle,
            max.map_or(0, |c| c) as c_int,
            Some(capturer),
            handler as *mut _,
        )
    };

    match result {
        0 => Ok(()),
        -2 => Err(Error::NoMorePackets),
        _ => capture.check_err(false),
    }
}

pub struct Packets<'a, T: Activated> {
    capture: &'a mut Capture<T>,
}

impl<'a, T: Activated> Iterator for Packets<'a, T> {
    type Item = Result<Packet<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let packet = self.capture.next();
        match packet {
            Ok(packet) => Some(Ok(packet)),
            Err(Error::NoMorePackets | Error::TimeoutExpired) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

impl<T: Activated> Capture<T> {
    pub fn iter(&mut self) -> Packets<T> {
        Packets { capture: self }
    }
}

/// NOTE: Localhost on windows takes only 4 bytes and not 10
#[derive(Debug, Clone, Copy)]
pub enum Snapshot {
    Custom(i32),
    EthernetII,
    IPv4,
    TCP,
    UDP,
    LocalIPv4,
    LocalTCP,
    LocalUDP,
    FullPacket,
}

#[cfg(target_os="linux")]
const LOCAL_ETHER_HEADER_SIZE: i32 = 16;

#[cfg(windows)]
const LOCAL_ETHER_HEADER_SIZE: i32 = 4;

// Check if this remove the calls in compile time, I think It can!
impl From<Snapshot> for i32 {
    fn from(s: Snapshot) -> Self {
        match s {
            #[cfg(target_os="linux")]
            Snapshot::EthernetII => 16,
            #[cfg(windows)]
            Snapshot::EthernetII => 14,

            Snapshot::Custom(len) => len,
            Snapshot::IPv4 => i32::from(Snapshot::EthernetII) + 20,
            Snapshot::TCP => i32::from(Snapshot::IPv4) + 20,
            Snapshot::UDP => i32::from(Snapshot::IPv4) + 8,
            Snapshot::LocalIPv4 => LOCAL_ETHER_HEADER_SIZE + 20,
            Snapshot::LocalTCP => i32::from(Snapshot::LocalIPv4) + 20,
            Snapshot::LocalUDP => i32::from(Snapshot::LocalIPv4) + 8,
            Snapshot::FullPacket => 65535,
        }
    }
}
