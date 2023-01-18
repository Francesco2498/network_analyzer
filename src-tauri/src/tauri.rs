
pub mod frontend_api {

  use pcap::{Device};
  use serde::Serialize;
  use crate::sniffer::{Sniffer, Status, Protocol, Direction};
  use tauri::State;
  use std::{sync::{Mutex, Arc}, collections::HashMap};

  /**
   * This Struct encapsulates a device that will be sent over 
   * to frontend. It will only contain data that makes sense to show
   * to the final user.
   */
  #[derive(Serialize)]
  pub struct DeviceRecord {
    id: String,
    name: String,
    ipv4_addr: String,
    netmask: String
  }
  impl DeviceRecord {
    pub fn new(dev: Device) -> Self {
        
      // Resolve Descriptive Name
      let name: String;
      match dev.desc {
        None => name = dev.name.clone(),
        Some(descriptive_name) => name = descriptive_name,
      }

      // Resolve Netmask Address
      let netmask: String;
      match dev.addresses[0].netmask {
        None => netmask = String::from(""),
        Some(existing_netmask) => netmask = existing_netmask.to_string(),
      }

      return DeviceRecord {
        id: dev.name,
        name,
        ipv4_addr: dev.addresses[0].addr.to_string(),
        netmask,
      }
    }
  }

  pub struct SnifferState(pub Mutex<Sniffer>);

  #[tauri::command]
  pub fn get_all_devices () -> Vec<DeviceRecord> {
    let devices = Sniffer::get_all_available_devices().unwrap().clone();

    let frontend_devices: Vec<DeviceRecord> = devices.into_iter()
    .filter(|dev| {
      // Return only running Devices
      return dev.flags.is_up() && dev.flags.is_running() && dev.addresses.len() > 0;
    })
    .map(|dev| DeviceRecord::new(dev)).collect();

    return frontend_devices;
  }

  #[tauri::command]
  pub fn set_device(device_name: String, sniffer: State<SnifferState>) -> Result<String, String> {
    
    let mut sniffer = sniffer.0.lock().unwrap();
    
    let devs_candidate: Vec<Device> = Sniffer::get_all_available_devices()
    .unwrap()
    .clone()
    .into_iter()
    .filter(|dev| {dev.name == device_name})
    .collect();

    if devs_candidate.len() == 0 {
      return Err(String::from("Error. No Device Found with this name!"));
    }

    let result = sniffer.set_device(devs_candidate[0].clone());

    match result {
      Ok(_) => Ok(String::from("OK")),
      Err(_) => Err(String::from("Could not Set the Device!"))
    }
  }

  #[tauri::command]
  pub fn get_device(sniffer: State<SnifferState>) -> Result<DeviceRecord, String> {
    let sniffer = sniffer.0.lock().unwrap();
    
    match sniffer.get_device() {
      Some(device) => Ok(DeviceRecord::new(device.clone())),
      None => Err(String::from("Error. Could Not find a device associated."))
    }
  }

  #[tauri::command]
  pub fn start_sniffer(sniffer: State<SnifferState>) -> Result<String, String> {
    let mut sniffer = sniffer.0.lock().unwrap();

    println!("API: executing START SNIFFER command");

    if sniffer.get_status() == Status::Idle {
      match sniffer.run() {
        Ok(_) => Ok(String::from("OK. Sniffer Started")),
        Err(_) => Err(String::from("Error while starting sniffer")),
      }
    }
    else if sniffer.get_status() == Status::Waiting {
      match sniffer.restart() {
        Ok(_) => Ok(String::from("OK. Sniffer Restarted")),
        Err(_) => Err(String::from("Error while re-starting sniffer")),
      }
    }
    else {
      return Err(String::from("Sniffer already running"));
    }
  }
  
  #[tauri::command]
  pub fn stop_sniffer(sniffer: State<SnifferState>) -> Result<String, String> {

    println!("API: executing STOP SNIFFER command");

    let mut sniffer = sniffer.0.lock().unwrap();
    let result = sniffer.stop();

    println!("API: successfully executed STOP SNIFFER command");

    match result {
      Ok(_) => Ok(String::from("OK. Sniffer Stopped.")),
      Err(_) => Err(String::from("Error. Could not stop the sniffer"))
    }
  }

  #[tauri::command]
  pub fn pause_sniffer(sniffer: State<SnifferState>) -> Result<String, String> {

    println!("API: executing PAUSE SNIFFER command");

    let mut sniffer = sniffer.0.lock().unwrap();

    let result = sniffer.wait();
    
    println!("API: successfully executed PAUSE SNIFFER command");

    match result {
      Ok(_) => Ok(String::from("OK. Sniffer Paused.")),
      Err(_) => Err(String::from("Error. Could not pause the sniffer"))
    }
  }

  /**
   * This Struct encapsulates the Packet details that will be sent over 
   * to frontend. It will only contain data that makes sense to show
   * to the final user.
   */
  #[derive(Serialize)]
  pub struct PacketRecord {
    address: String,
    port: String,
    protocol: String,
    bytes_tx: String,
    direction: String,
    start: String,
    end: String,
  }

  fn parse_hashmap(hashmap: Arc<Mutex<HashMap<(String, u16), (Protocol, usize, Direction, String, String)>>>) -> Vec<PacketRecord> {
      let mut res: Vec<PacketRecord> = vec![];
      let hm = hashmap.clone();

      for (key, value) in hm.lock().unwrap().iter() {
        res.push(
          PacketRecord { 
            address: key.0.clone(),
            port: key.1.to_string(), 
            protocol: value.0.to_string(), 
            bytes_tx: value.1.to_string(), 
            direction: value.2.to_string(), 
            start: value.3.clone(), 
            end: value.4.clone() 
        });
      }

      return res;
  }

  #[tauri::command]
  pub fn get_sniffed_data(sniffer: State<SnifferState>) -> Result<Vec<PacketRecord>, String> {

    let sniffer = sniffer.0.lock().unwrap();

    let records = parse_hashmap(sniffer.get_hashmap().clone());

    return Ok(records);
  }

  #[tauri::command]
  pub fn generate_report(file_name: String, sniffer: State<SnifferState>) -> Result<(), String> {
    let mut sniffer = sniffer.0.lock().unwrap();
    
    sniffer.stop().unwrap();
    sniffer.set_file(file_name).unwrap();
    sniffer.generate_report().unwrap();

    return Ok(())
  }

}
