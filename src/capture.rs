use crate::{raw, Capture, PacketHeader};
use crate::{Activated, Error, Packet, State};
use etherparse::{Ipv4HeaderSlice, SlicedPacket};
use libc::{c_int, c_uchar};

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

impl<T: Activated> Capture<T> {
    pub fn iter(&mut self) -> PacketsIter<T> {
        PacketsIter { capture: self }
    }
}

/// An iterator for the captures packets
/// returns None on timeout or no more packets from pcap file
pub struct PacketsIter<'a, T: Activated> {
    capture: &'a mut Capture<T>,
}

impl<'a, T: Activated> Iterator for PacketsIter<'a, T> {
    type Item = Packet<'a>;

    /// Since the only errors are where there are no more packets (from the file or got
    /// timeout) we can ignore the error
    fn next(&mut self) -> Option<Self::Item> {
        let packet = self.capture.next();
        match packet {
            Ok(packet) => Some(packet),
            Err(_) => None,
        }
    }
}

impl<'a, T: Activated> PacketsIter<'a, T> {
    pub fn parse_ethernet(&'a mut self) -> EtherIter<'a, T> {
        EtherIter { iter: self }
    }

    pub fn parse_ip(&'a mut self) -> IpIter<'a, T> {
        IpIter { iter: self }
    }
}

/// A wrapper for the packets using
/// (etherparse)[https://docs.rs/etherparse/latest/etherparse/struct.SlicedPacket.html#method.from_ethernet] parsing capabilities.
/// This function assumes the given data starts with an ethernet II header 14 byte length.
/// ### Important 
/// On windows localhost the ether header is only the type and will **not** work with etherparse,
/// try to parse it yourself instead or use `Ipv4HeaderSlice::from_slice(&packet.data[4..])` for IP
/// parsing
pub struct EtherIter<'a, T: Activated> {
    iter: &'a mut PacketsIter<'a, T>,
}

impl<'a, T: Activated> Iterator for EtherIter<'a, T> {
    type Item = Result<SlicedPacket<'a>, etherparse::ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        let packet = self.iter.next()?;
        Some(SlicedPacket::from_ethernet(packet.data))
    }
}

/// A wrapper for the packets using
/// (etherparse IPv4)[https://docs.rs/etherparse/latest/etherparse/struct.Ipv4HeaderSlice.html#method.from_slice] parsing capabilities.
/// This function assumes the Ip Header starts at index 14 (like a normal packet).
/// ### Important 
/// On windows localhost the ether header is only the type and will **not** work with etherparse,
/// try to parse it yourself instead or use `Ipv4HeaderSlice::from_slice(&packet.data[4..])` for IP
/// parsing
pub struct IpIter<'a, T: Activated> {
    iter: &'a mut PacketsIter<'a, T>,
}

impl<'a, T: Activated> Iterator for IpIter<'a, T> {
    type Item = Result<Ipv4HeaderSlice<'a>, etherparse::ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        let packet = self.iter.next()?;
        if packet.data.len() < 14 {
            return Some(Err(etherparse::ReadError::UnexpectedEndOfSlice(14)));
        }

        Some(Ipv4HeaderSlice::from_slice(&packet.data[14..]))
    }
}
