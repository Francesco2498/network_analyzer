export interface BackendDevice {
  id: string,
  name: string,
  ipv4_addr: string,
  netmask: string
}

export interface Packet {
    address: string,
    port: string,
    protocol: string,
    bytes_tx: string,
    direction: string,
    start: string,
    end: string,
}