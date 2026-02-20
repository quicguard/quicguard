// TUN interface management for Linux

use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::process::Command;
use tracing::{debug, info, warn};



use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};

use tun::AsyncDevice;

use std::os::unix::io::{AsRawFd, RawFd};


use std::io::{Read, Write};

#[cfg(target_os = "linux")]
struct RawTunFd {
    fd: RawFd,
}

#[cfg(target_os = "linux")]
impl AsRawFd for RawTunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

#[cfg(target_os = "linux")]
impl Read for RawTunFd {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let ret = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }
}

#[cfg(target_os = "linux")]
impl Write for RawTunFd {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let ret = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for RawTunFd {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

// ============================================================================
// Standard tokio-based TUN implementation
// ============================================================================
pub struct TunReader {
    inner: TunReaderInner,
}
enum TunReaderInner {
    Standard(ReadHalf<AsyncDevice>),
}
/// TUN device writer half  
pub struct TunWriter {
    inner: TunWriterInner,
}
enum TunWriterInner {
    Standard(WriteHalf<AsyncDevice>),
}

impl TunReader {
    /// Read a packet from the TUN device
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match &mut self.inner {
            TunReaderInner::Standard(reader) => {
                let n = reader.read(buf).await?;
                debug!("Read {} bytes from TUN", n);
                Ok(n)
            }
           
        }
    }
}


impl TunWriter {
    /// Write a packet to the TUN device
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match &mut self.inner {
            TunWriterInner::Standard(writer) => {
                let n = writer.write(buf).await?;
                debug!("Wrote {} bytes to TUN", n);
                Ok(n)
            }
            
        }
    }
}



pub struct TunDevice {
    inner: TunDeviceInner,
    name: String,
}


enum TunDeviceInner {
    Standard(AsyncDevice),
}

impl TunDevice {
    /// Create a new TUN device 
    pub async fn new(name: &str) -> Result<Self> {
        let mut config = tun::Configuration::default();
        config
            .name(name)
            .layer(tun::Layer::L3)
            .up();

        #[cfg(target_os = "linux")]
        config.platform(|config| {
            config.packet_information(false);
        });

        let device = tun::create_as_async(&config)
            .context("Failed to create TUN device")?;

        info!("Created TUN device: {} (tokio async)", name);

        Ok(Self {
            inner: TunDeviceInner::Standard(device),
            name: name.to_string()
        })
    }

   
    /// Split the TUN device into separate read and write halves
    pub fn split(self) -> (TunReader, TunWriter) {
        match self.inner {
            TunDeviceInner::Standard(device) => {
                let (reader, writer) = tokio::io::split(device);
                (
                    TunReader { inner: TunReaderInner::Standard(reader) },
                    TunWriter { inner: TunWriterInner::Standard(writer) },
                )
            }            
        }
    }

    /// Get the device name
    pub fn name(&self) -> &str {
        &self.name
    }
}



unsafe impl Sync for TunReader {}
unsafe impl Send for TunWriter {}


impl TunDevice {
    /// Configure the TUN device with IP address and bring it up
    /// Note: Call this BEFORE splitting the device
    pub fn configure(name: &str, ip: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> Result<()> {
        // Set IP address
        let output = Command::new("ip")
            .args(["addr", "add", &format!("{}/{}", ip, netmask_to_cidr(netmask)), "dev", name])
            .output()
            .context("Failed to run ip addr add")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "file exists" error (address already set)
            if !stderr.contains("File exists") {
                anyhow::bail!("Failed to set IP address: {}", stderr);
            }
        }

        // Set MTU
        let output = Command::new("ip")
            .args(["link", "set", "dev", name, "mtu", &mtu.to_string()])
            .output()
            .context("Failed to run ip link set mtu")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to set MTU: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Bring interface up
        let output = Command::new("ip")
            .args(["link", "set", "dev", name, "up"])
            .output()
            .context("Failed to run ip link set up")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to bring interface up: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        info!(
            "Configured TUN device {} with IP {}/{}, MTU {}",
            name, ip, netmask_to_cidr(netmask), mtu
        );

        Ok(())
    }

    /// Add a route through this TUN device
    pub fn add_route(&self, network: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
        let cidr = netmask_to_cidr(netmask);
        let output = Command::new("ip")
            .args([
                "route",
                "add",
                &format!("{}/{}", network, cidr),
                "dev",
                &self.name,
            ])
            .output()
            .context("Failed to run ip route add")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                anyhow::bail!("Failed to add route: {}", stderr);
            }
        }

        info!("Added route {}/{} via {}", network, cidr, self.name);
        Ok(())
    }

    /// Set default route through this TUN device
    pub fn set_default_route(&self, gateway: Ipv4Addr) -> Result<()> {
        let output = Command::new("ip")
            .args([
                "route",
                "add",
                "default",
                "via",
                &gateway.to_string(),
                "dev",
                &self.name,
            ])
            .output()
            .context("Failed to run ip route add default")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("File exists") {
                anyhow::bail!("Failed to set default route: {}", stderr);
            }
        }

        info!("Set default route via {} through {}", gateway, self.name);
        Ok(())
    }
}

/// Convert netmask to CIDR notation
fn netmask_to_cidr(netmask: Ipv4Addr) -> u8 {
    let octets = netmask.octets();
    let mut cidr = 0u8;
    for octet in octets {
        cidr += octet.count_ones() as u8;
    }
    cidr
}

/// Enable IP forwarding on the system (for server)
pub fn enable_ip_forwarding() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .context("Failed to enable IP forwarding")?;
    info!("Enabled IP forwarding");
    Ok(())
}

/// Setup NAT for the tunnel network (for server)
pub fn setup_nat(tun_network: &str, external_interface: &str) -> Result<()> {
    // Enable masquerading
    let output = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            tun_network,
            "-o",
            external_interface,
            "-j",
            "MASQUERADE",
        ])
        .output()
        .context("Failed to run iptables")?;

    if !output.status.success() {
        anyhow::bail!(
            "Failed to setup NAT: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Allow forwarding for tunnel
    let output = Command::new("iptables")
        .args([
            "-A",
            "FORWARD",
            "-s",
            tun_network,
            "-j",
            "ACCEPT",
        ])
        .output()
        .context("Failed to run iptables forward")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("already") {
            anyhow::bail!("Failed to setup forwarding: {}", stderr);
        }
    }

    let output = Command::new("iptables")
        .args([
            "-A",
            "FORWARD",
            "-d",
            tun_network,
            "-j",
            "ACCEPT",
        ])
        .output()
        .context("Failed to run iptables forward return")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("already") {
            anyhow::bail!("Failed to setup return forwarding: {}", stderr);
        }
    }

    info!("Setup NAT for {} via {}", tun_network, external_interface);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netmask_to_cidr() {
        assert_eq!(netmask_to_cidr(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(netmask_to_cidr(Ipv4Addr::new(255, 255, 0, 0)), 16);
        assert_eq!(netmask_to_cidr(Ipv4Addr::new(255, 0, 0, 0)), 8);
        assert_eq!(netmask_to_cidr(Ipv4Addr::new(255, 255, 255, 255)), 32);
    }
}
