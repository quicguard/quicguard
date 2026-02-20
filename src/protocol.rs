// QuicGuard protocol for tunneling over HTTP/3 QUIC
// This implements a simplified CONNECT-UDP style protocol

use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

/// Magic bytes to identify our protocol
pub const PROTOCOL_MAGIC: u32 = 0x4D415351; // "MASQ"

/// Protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum packet size (MTU for tunnel)
pub const MAX_PACKET_SIZE: usize = 1500;

/// Maximum datagram size for QUIC
pub const MAX_DATAGRAM_SIZE: usize = 65535;

/// Message types for the QuicGuard protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    /// Client hello - initiate connection
    ClientHello = 0x01,
    /// Server hello - acknowledge connection
    ServerHello = 0x02,
    /// IP packet data
    IpPacket = 0x03,
    /// Keepalive
    Keepalive = 0x04,
    /// Disconnect
    Disconnect = 0x05,
    /// Error message
    ErrorMsg = 0x06,
}

impl TryFrom<u8> for MessageType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        match value {
            0x01 => Ok(MessageType::ClientHello),
            0x02 => Ok(MessageType::ServerHello),
            0x03 => Ok(MessageType::IpPacket),
            0x04 => Ok(MessageType::Keepalive),
            0x05 => Ok(MessageType::Disconnect),
            0x06 => Ok(MessageType::ErrorMsg),
            _ => Err("Unknown message type"),
        }
    }
}

/// Client hello message - sent when initiating tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub version: u8,
    pub client_id: [u8; 16], // UUID-like identifier
    pub requested_ip: Option<Ipv4Addr>,
}

/// Server hello response - contains assigned tunnel IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHello {
    pub version: u8,
    pub assigned_ip: Ipv4Addr,
    pub server_ip: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
}

/// Protocol message wrapper
#[derive(Debug, Clone)]
pub struct Message {
    pub msg_type: MessageType,
    pub payload: Bytes,
}

impl Message {
    pub fn new(msg_type: MessageType, payload: impl Into<Bytes>) -> Self {
        Self {
            msg_type,
            payload: payload.into(),
        }
    }

    /// Encode message to bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(9 + self.payload.len());
        buf.put_u32(PROTOCOL_MAGIC);
        buf.put_u8(PROTOCOL_VERSION);
        buf.put_u8(self.msg_type as u8);
        buf.put_u16(self.payload.len() as u16);
        buf.put_slice(&self.payload);
        buf.freeze()
    }

    /// Decode message from bytes
    pub fn decode(mut data: Bytes) -> Result<Self, &'static str> {
        if data.len() < 8 {
            return Err("Message too short");
        }

        let magic = data.get_u32();
        if magic != PROTOCOL_MAGIC {
            return Err("Invalid magic bytes");
        }

        let version = data.get_u8();
        if version != PROTOCOL_VERSION {
            return Err("Unsupported protocol version");
        }

        let msg_type = MessageType::try_from(data.get_u8())?;
        let payload_len = data.get_u16() as usize;

        if data.len() < payload_len {
            return Err("Payload length mismatch");
        }

        let payload = data.copy_to_bytes(payload_len);

        Ok(Self { msg_type, payload })
    }

    /// Create a client hello message
    pub fn client_hello(client_id: [u8; 16], requested_ip: Option<Ipv4Addr>) -> Self {
        let hello = ClientHello {
            version: PROTOCOL_VERSION,
            client_id,
            requested_ip,
        };
        let payload = bincode::serialize(&hello).unwrap();
        Self::new(MessageType::ClientHello, payload)
    }

    /// Create a server hello message
    pub fn server_hello(
        assigned_ip: Ipv4Addr,
        server_ip: Ipv4Addr,
        subnet_mask: Ipv4Addr,
        dns_servers: Vec<Ipv4Addr>,
    ) -> Self {
        let hello = ServerHello {
            version: PROTOCOL_VERSION,
            assigned_ip,
            server_ip,
            subnet_mask,
            dns_servers,
        };
        let payload = bincode::serialize(&hello).unwrap();
        Self::new(MessageType::ServerHello, payload)
    }

    /// Create an IP packet message
    pub fn ip_packet(data: impl Into<Bytes>) -> Self {
        Self::new(MessageType::IpPacket, data)
    }

    /// Create a keepalive message
    pub fn keepalive() -> Self {
        Self::new(MessageType::Keepalive, Bytes::new())
    }

    /// Create a disconnect message
    pub fn disconnect() -> Self {
        Self::new(MessageType::Disconnect, Bytes::new())
    }

    /// Parse payload as ClientHello
    pub fn parse_client_hello(&self) -> Result<ClientHello, &'static str> {
        if self.msg_type != MessageType::ClientHello {
            return Err("Not a ClientHello message");
        }
        bincode::deserialize(&self.payload).map_err(|_| "Failed to parse ClientHello")
    }

    /// Parse payload as ServerHello
    pub fn parse_server_hello(&self) -> Result<ServerHello, &'static str> {
        if self.msg_type != MessageType::ServerHello {
            return Err("Not a ServerHello message");
        }
        bincode::deserialize(&self.payload).map_err(|_| "Failed to parse ServerHello")
    }
}

/// Extract destination IP from an IP packet
pub fn extract_dest_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }

    let version = (packet[0] >> 4) & 0x0F;
    match version {
        4 => {
            // IPv4
            if packet.len() < 20 {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                packet[16],
                packet[17],
                packet[18],
                packet[19],
            )))
        }
        6 => {
            // IPv6
            if packet.len() < 40 {
                return None;
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(addr.into()))
        }
        _ => None,
    }
}

/// Extract source IP from an IP packet
pub fn extract_src_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }

    let version = (packet[0] >> 4) & 0x0F;
    match version {
        4 => {
            // IPv4
            if packet.len() < 20 {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                packet[12],
                packet[13],
                packet[14],
                packet[15],
            )))
        }
        6 => {
            // IPv6
            if packet.len() < 40 {
                return None;
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&packet[8..24]);
            Some(IpAddr::V6(addr.into()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_encode_decode() {
        let msg = Message::ip_packet(vec![1, 2, 3, 4]);
        let encoded = msg.encode();
        let decoded = Message::decode(encoded).unwrap();
        assert_eq!(decoded.msg_type, MessageType::IpPacket);
        assert_eq!(&decoded.payload[..], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_client_hello() {
        let client_id = [1u8; 16];
        let msg = Message::client_hello(client_id, Some(Ipv4Addr::new(10, 0, 0, 2)));
        let encoded = msg.encode();
        let decoded = Message::decode(encoded).unwrap();
        let hello = decoded.parse_client_hello().unwrap();
        assert_eq!(hello.client_id, client_id);
        assert_eq!(hello.requested_ip, Some(Ipv4Addr::new(10, 0, 0, 2)));
    }
}
