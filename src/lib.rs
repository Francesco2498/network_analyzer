// analyzing incoming and outgoing traffic through the network interfaces of a computer.

extern crate core;
extern crate prettytable;
pub mod sniffer {
    use std::collections::HashMap;
    use std::{fmt, thread};
    use std::fmt::{Display, Formatter};
    use std::fs::{File, OpenOptions};
    use std::io::{Seek, Write};
    use std::path::Path;
    use std::sync::{Arc, Condvar, Mutex};
    use std::sync::mpsc::channel;
    use std::time::Duration;
    use pcap::{Capture, Device, Packet};
    use pktparse::{ethernet, ipv4, ipv6};
    use pktparse::ethernet::EtherType;
    use pktparse::ip::IPProtocol;
    use pktparse::ipv4::{IPv4Header, parse_ipv4_header};
    use pktparse::ipv6::{IPv6Header, parse_ipv6_header};
    use pktparse::tcp::parse_tcp_header;
    use pktparse::udp::parse_udp_header;
    use prettytable::{Cell, row, Row, Table};
    use chrono::{Local};


    //ERRORE CUSTOMIZZATO
    #[derive(Debug, Clone)]
    pub enum NetworkAnalyzerError {
        PacketDecodeError(String),
        UserError(String),
        UserWarning(String),
        PcapError(String)
    }

    impl Display for NetworkAnalyzerError {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            match self {
                NetworkAnalyzerError::PacketDecodeError(e)  => write!(f, "{}", e),
                NetworkAnalyzerError::UserError(e)  => write!(f, "{}", e),
                NetworkAnalyzerError::UserWarning(e)  => write!(f, "{}", e),
                NetworkAnalyzerError::PcapError(e)  => write!(f, "{}", e),
            }
        }
    }

    //ENUM CHE SERVE PER DIRE SE IL PACCHETTO E' STATO INVIATO O RICEVUTO
    #[derive(Debug, Clone, PartialEq)]
    pub enum Direction {
        Received,
        Transmitted
    }

    impl Display for Direction {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{:?}", self)
        }
    }
    /*
    #[derive(Debug, Clone, PartialEq)]
    struct PacketToSend <'a>{
        data: &'a [u8]
    }

    impl <'a> PacketToSend<'a> {
        pub fn new(data: &'a[u8]) -> Self {
            PacketToSend{
                data
            }
        }
    }
     */

    //we need it because IPProtocol doesn't have the trait Display or ToString
    #[derive(Debug, Clone)]
    pub enum Protocol {
        TCP,
        UDP
    }

    impl Display for Protocol {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "{:?}", self)
        }
    }

    //INFO ESTRATTE CHE VERRANNO STAMPATE NEL REPORT
    #[derive(Debug, Clone)]
    pub struct PacketResult {
        address: String,
        port: u16,
        protocol: Protocol,
        byte_transmitted: usize,
        direction:Direction
    }

    impl PacketResult {
        pub fn new(address: String, port: u16, protocol: Protocol, byte_transmitted: usize, direction : Direction) -> Self {
            PacketResult { address, port, protocol, byte_transmitted, direction}
        }

        pub fn get_address(&self) -> String { return self.address.clone() }
        pub fn get_port(&self) -> u16 { return self.port }
        pub fn get_protocol(&self) -> Protocol { return self.protocol.clone() }
        pub fn get_byte_transmitted(&self) -> usize { return self.byte_transmitted }
        pub fn get_direction(&self) -> Direction { return self.direction.clone() }
    }

    fn get_direction_ipv4(header: IPv4Header, device: Device) -> Direction {
        if device.addresses.iter().any(|a| a.addr.to_string() == header.dest_addr.to_string()) {
            Direction::Transmitted
        } else { Direction::Received }
    }

    fn  get_direction_ipv6(header: IPv6Header, device: Device) -> Direction {
        if device.addresses.iter().any(|a| a.addr.to_string() == header.dest_addr.to_string()) {
            Direction::Transmitted
        } else { Direction::Received }
    }

    fn extract_info_from_packet(device: Device, packet : Packet) -> Result<PacketResult, NetworkAnalyzerError> {
       if let Ok((remainingEt, eth_frame)) = ethernet::parse_ethernet_frame(packet.data) {
           return match eth_frame.ethertype {
               EtherType::IPv4 => {

                  if let Ok((remainingIp, ipv4_header)) = parse_ipv4_header(remainingEt) {
                      let direction = get_direction_ipv4(ipv4_header.clone(), device.clone());
                      match ipv4_header.protocol {
                          IPProtocol::UDP => {
                              if let Ok((remainingUDP, udp_header)) = parse_udp_header(remainingIp) {
                                  let byte_transmitted = 5;
                                  let address;
                                  let port;
                                  if direction == Direction::Received {
                                      address = ipv4_header.source_addr.to_string();
                                      port = udp_header.source_port;
                                  } else {
                                      address = ipv4_header.dest_addr.to_string();
                                      port = udp_header.dest_port;
                                  }
                                  Ok(PacketResult::new(address, port, Protocol::UDP, byte_transmitted, direction))
                              } else {
                                  Err(NetworkAnalyzerError::PacketDecodeError("Error while parsing udp packet".parse().unwrap()))
                              }
                          },
                          IPProtocol::TCP => {
                              if let Ok((remainingTCP, tcp_header)) = parse_tcp_header(remainingIp) {
                                  let byte_transmitted = 5;
                                  let address;
                                  let port;
                                  if direction == Direction::Received {
                                      address = ipv4_header.source_addr.to_string();
                                      port = tcp_header.source_port;
                                  } else {
                                      address = ipv4_header.dest_addr.to_string();
                                      port = tcp_header.dest_port;
                                  }
                                  Ok(PacketResult::new(address, port, Protocol::TCP, byte_transmitted, direction))
                              } else {
                                  Err(NetworkAnalyzerError::PacketDecodeError("Error while parsing tcp packet".parse().unwrap()))
                              }
                          },
                          _ => Err(NetworkAnalyzerError::PacketDecodeError("Trasport level protocol not found. Only UDP and TCP are permitted.".parse().unwrap())),
                      }
                  } else {
                      Err(NetworkAnalyzerError::PacketDecodeError("Error while parsing ipv4 packet".parse().unwrap()))
                  }
               },
               EtherType::IPv6 => {
                   if let Ok((remainingIp, ipv6_header)) = parse_ipv6_header(remainingEt) {
                       let direction = get_direction_ipv6(ipv6_header.clone(), device.clone());

                       match ipv6_header.next_header {
                           IPProtocol::UDP => {
                               if let Ok((remainingUDP, udp_header)) = parse_udp_header(remainingIp) {
                                   let byte_transmitted = 5;
                                   let address;
                                   let port;
                                   if direction == Direction::Received {
                                       address = ipv6_header.source_addr.to_string();
                                       port = udp_header.source_port;
                                   } else {
                                       address = ipv6_header.dest_addr.to_string();
                                       port = udp_header.dest_port;
                                   }
                                   Ok(PacketResult::new(address, port, Protocol::UDP, byte_transmitted, direction))
                               } else {
                                   Err(NetworkAnalyzerError::PacketDecodeError("Error while parsing udp packet".parse().unwrap()))
                               }
                           },
                           IPProtocol::TCP => {
                               if let Ok((remainingTCP, tcp_header)) = parse_tcp_header(remainingIp) {
                                   let byte_transmitted = 5;
                                   let address;
                                   let port;
                                   if direction == Direction::Received {
                                       address = ipv6_header.source_addr.to_string();
                                       port = tcp_header.source_port;
                                   } else {
                                       address = ipv6_header.dest_addr.to_string();
                                       port = tcp_header.dest_port;
                                   }
                                   Ok(PacketResult::new(address, port, Protocol::TCP, byte_transmitted, direction))
                               } else {
                                   Err(NetworkAnalyzerError::PacketDecodeError("Error while parsing tcp packet".parse().unwrap()))
                               }
                           },
                           _ => Err(NetworkAnalyzerError::PacketDecodeError("Trasport level protocol not found. Only UDP and TCP are permitted.".parse().unwrap())),
                       }
                   } else {
                       Err(NetworkAnalyzerError::PacketDecodeError("Error while parsing ipv6 packet".parse().unwrap()))
                   }
               },
               _ => Err(NetworkAnalyzerError::PacketDecodeError("Ip level protocol not found. Only IPv4 and IPv6 are permitted.".parse().unwrap())),
           };
       } else {
           Err(NetworkAnalyzerError::PacketDecodeError("Level 2 protocol not found. Only Ethernet is permitted.".parse().unwrap()))
       }
    }

    // i diversi stati dell'applicazione
    #[derive(PartialEq, Debug, Clone, Eq)]
    pub enum Status {
        // Al bootstrap o quando viene salvato il report
        Idle,
        // Lo sniffing può essere messo in pausa usando il metodo wait
        Waiting,
        // Processo in esecuzione
        Running,
        // Stato di errore
        Error(String)
    }

    pub struct Sniffer {
        device: Option<pcap::Device>,
        status: Arc<(Mutex<Status>, Condvar)>,
        file: Option<String>,
        time_interval: u64,
        hashmap: Arc<Mutex<HashMap<(String, u16), (Protocol, usize, Direction)>>>,
    }

    impl Sniffer {

        pub fn new() -> Self {
            return Sniffer {
                device: None,
                status: Arc::new((Mutex::new(Status::Idle), Condvar::new())),
                file: None,
                time_interval: 0,
                hashmap: Arc::new(Mutex::new(HashMap::new()))
            }
        }

        pub fn get_time_interval(&self) -> u64 {
            self.time_interval
        }

        pub fn set_time_interval(&mut self, time_interval: u64) {
            self.time_interval = time_interval;
        }

        pub fn get_status(&self) -> Status {
            let s = self.status.0.lock().unwrap();
            return (*s).clone();
        }

        pub fn set_status(&self, status: Status) -> () {
            let mut s = self.status.0.lock().unwrap();
            *s = status;
        }

        pub fn get_device(&self) -> &Option<pcap::Device> {
            &self.device
        }

        pub fn set_device(&mut self, device: pcap::Device) -> Result<(), NetworkAnalyzerError> {
            return match Sniffer::get_all_available_devices() {
                Ok(devices) => {
                    for dev in &devices {
                        if dev.name == device.name {
                            self.device = Some(device);
                            return Ok(())
                        }
                    }
                    return Err(NetworkAnalyzerError::UserError("The device selected is not available".to_string()))
                },
                Err(error) => Err(error)
            }
        }

        pub fn get_hashmap(&self) -> &Arc<Mutex<HashMap<(String, u16), (Protocol, usize, Direction)>>> {
            &self.hashmap
        }

        pub fn get_file(&self) -> Option<String> {
            self.file.clone()
        }

        pub fn set_file(&mut self, filename: String) -> Result<(), NetworkAnalyzerError> {
            let file = File::create(Path::new(&filename));
            match file {
                Ok(_) => {
                    self.file = Some(filename);
                    Ok(())
                },
                Err(_) => Err(NetworkAnalyzerError::UserError("Error while file creation.".to_string()))
            }
        }

        pub fn get_all_available_devices() -> Result<Vec<pcap::Device>, NetworkAnalyzerError> {
            let devices = pcap::Device::list();
            return match devices {
                Ok(devices) => Ok(devices),
                Err(e) => Err(NetworkAnalyzerError::PcapError(e.to_string())),
            }
        }

        pub fn wait(&mut self) -> Result<(), NetworkAnalyzerError> {
            let status = self.get_status();
            match &status {
                Status::Running => {
                    self.set_status(Status::Waiting);
                    Ok(())
                },
                Status::Error(error) => Err(NetworkAnalyzerError::UserError(error.to_string())),
                Status::Idle => { return Err(NetworkAnalyzerError::UserWarning("There is no sniffing process in execution.".to_string())); },
                Status::Waiting => { return Err(NetworkAnalyzerError::UserWarning("The sniffing process is already stopped.".to_string())); }
            }
        }

        pub fn restart(&mut self) -> Result<(), NetworkAnalyzerError> {
            let status = self.get_status();
            match &status {
                Status::Waiting => {
                    self.set_status(Status::Running);
                    self.status.1.notify_all();
                    Ok(())
                },
                Status::Error(error) => Err(NetworkAnalyzerError::UserError(error.to_string())),
                Status::Idle => { return Err(NetworkAnalyzerError::UserWarning("The sniffing process is already stopped.".to_string())); },
                Status::Running => { return Err(NetworkAnalyzerError::UserWarning("The sniffing process is already running.".to_string())); }
            }
        }

        pub fn run(&mut self) -> Result<(), NetworkAnalyzerError> {
            let status = self.get_status();
            return match &status {
                Status::Idle => {
                    if self.get_file().is_none() {
                        return Err(NetworkAnalyzerError::UserError("FileName is blank.".to_string()));
                    }
                    if self.get_device().is_none() {
                        return Err(NetworkAnalyzerError::UserError("Missing device".to_string()));
                    }

                    self.set_status(Status::Running);
                    let device = self.get_device().clone().unwrap();
                    let tuple = Arc::clone(&self.status.clone());

                    let hashmap = self.get_hashmap().clone();

                    let sender = thread::spawn(move || {
                        let cloned_device = device.clone();
                        let mut cap = Capture::from_device(cloned_device.clone()).unwrap().promisc(true).open().unwrap();
                        let mut status = tuple.0.lock().unwrap();

                        loop {
                            match *status {
                                Status::Running => {
                                    match cap.next_packet() {
                                        Ok(packet)  => {
                                            match extract_info_from_packet(cloned_device.clone(), packet) {
                                                Ok(info) => {
                                                    let mut hm = hashmap.lock().unwrap();
                                                    let existing_pkt = hm.get(&(info.get_address(), info.get_port()));
                                                    match existing_pkt {
                                                        None => {
                                                            hm.insert((info.get_address(), info.get_port()),
                                                                      (info.get_protocol(), info.get_byte_transmitted(), info.get_direction()));
                                                        },
                                                        value => {
                                                            let bytes = info.get_byte_transmitted() + value.unwrap().clone().1;
                                                            hm.insert((info.get_address(), info.get_port()),
                                                                      (info.get_protocol(), bytes, info.get_direction()));
                                                        }
                                                    }
                                                },
                                                Err(_) => {}
                                            }
                                        }
                                        Err(error) => {
                                            NetworkAnalyzerError::PcapError(error.to_string());
                                        }
                                    }
                                },
                                Status::Waiting => {
                                    status = tuple.1.wait_while(status, |status| { *status == Status::Waiting }).unwrap();
                                },
                                Status::Idle => { break; }
                                Status::Error(_) => { println!("Unexpected Error."); break; }
                            }
                            thread::sleep(Duration::from_millis(1));
                        };
                    });

                    Ok(())
                },
                _ => {return Err(NetworkAnalyzerError::UserWarning("Another sniffing process is already running.".to_string()))}
            }
        }


        //run with interval TODO

        fn print_title(device: &Device) -> String {
            let mut string = "Device sniffed: ".to_string();
            string.push_str(device.name.as_str());
            string.push_str("\nAddresses: ");
            device.addresses.iter().for_each(|a| {
                string.push_str("\n\t- ");
                string.push_str(a.addr.to_string().as_str());
            });
            return string
        }

        fn print_table(hashmap: Arc<Mutex<HashMap<(String, u16), (Protocol, usize, Direction)>>>) -> String {
            let mut res = "Scanning: \n\t- Timestamp: ".to_string();
            res.push_str(Local::now().to_string().as_str());
            let mut table = Table::new();
            table.add_row(row!["IP Address", "Port", "Protocol", "Bytes Transmitted", "Direction"]);
            let hm = hashmap.clone();
            for (key, value) in hm.lock().unwrap().iter() {
                table.add_row(Row::new(vec![
                    Cell::new(key.0.as_str()),
                    Cell::new(key.1.to_string().as_str()),
                    Cell::new(value.0.to_string().as_str()),
                    Cell::new(value.1.to_string().as_str()),
                    Cell::new(value.2.to_string().as_str())
                ]));
            }
            res.push_str("\n");
            res.push_str(table.to_string().as_str());
            return res
        }

        pub fn generate_report(&self) -> Result<String, NetworkAnalyzerError> {
            let status = self.get_status();
            match &status {
                Status::Error(error) => Err(NetworkAnalyzerError::UserError(error.to_string())),
                Status::Idle => { Err(NetworkAnalyzerError::UserWarning("The process is already stopped.".to_string())) },
                _ => {
                    if self.get_file().is_none() {
                        Err(NetworkAnalyzerError::UserError("The file name is blank.".to_string()))
                    } else {
                        let write;
                        let body;
                        if self.get_time_interval() == 0 {
                            let mut file = match OpenOptions::new().write(true).open(self.get_file().unwrap()) {
                                Ok(file) => file,
                                Err(_) => return Err(NetworkAnalyzerError::UserError("Cannot open the file.".to_string()))
                            };
                            match file.rewind() { //porta la testina all'inizio del file
                                Ok(_) => (),
                                Err(_) =>  return Err(NetworkAnalyzerError::UserError("Requind operation goes wrong.".to_string()))
                            };

                            let mut title = Sniffer::print_title(&self.device.as_ref().unwrap().clone());
                            body = Sniffer::print_table(self.get_hashmap().clone());
                            title.push_str(body.as_str());

                            write = file.write(title.as_bytes());
                        } else {
                            let mut file = match OpenOptions::new().append(true).open(self.get_file().unwrap()) {
                                Ok(file) => file,
                                Err(_) => return Err(NetworkAnalyzerError::UserError("Cannot open the file.".to_string()))

                            };
                            body = Sniffer::print_table(self.get_hashmap().clone());
                            write = file.write(body.as_bytes());
                        }
                        return match write {
                            Ok(_) => {
                                self.set_status(Status::Idle);
                                Ok("The report has been saved and the scanning has been stopped.".to_string())
                            },
                            Err(error) => Err(NetworkAnalyzerError::UserError(error.to_string()))
                        }
                    }
                },
            }
        }

    }


    }