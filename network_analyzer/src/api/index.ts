import { Device } from "../models/network";
import { invoke } from '@tauri-apps/api/tauri'
import { BackendDevice, Packet } from "../models/rust_structs";

export class BackendAPI {

  static async getAllDevices (): Promise<Device[]> {
    console.log("Getting Device from Backend");
    const devicesFromBE: BackendDevice[] = await invoke('get_all_devices');

    return devicesFromBE.map((dev: BackendDevice): Device => {
      return {
        id: dev.id,
        name: dev.name,
        ipv4Address: dev.ipv4_addr,
        netmask: dev.netmask 
      }
    });
  }

  static async setDevice(deviceId: string): Promise<void> {
    console.log(`Setting device to: ${deviceId}`);
    const response: string = await invoke('set_device', {deviceName: deviceId});
    console.log(`Response from Back-end is: ${response}`);
  }

  static async getDevice(): Promise<Device> {
    console.log("Getting Device from Backend");

    const deviceFromBE: BackendDevice = await invoke('get_device');

    return {
      id: deviceFromBE.id,
      name: deviceFromBE.name,
      ipv4Address: deviceFromBE.ipv4_addr,
      netmask: deviceFromBE.netmask 
    }
  }

  static async startOrResumeSniffer(): Promise<void> {
    const result: String = await invoke('start_sniffer');

    console.log(`Started Sniffer. Backend responded with: ${result}`);
  }

  static async pauseSniffer(): Promise<void> {
    const result: String = await invoke('pause_sniffer');

    console.log(`Success. Backend responded with: ${result}`);
  }

  static async stopSniffer(): Promise<void> {
    const result: String = await invoke('stop_sniffer');

    console.log(`Success. Backend responded with: ${result}`); 
  }

  static async getNetworkData(): Promise<Packet[]> {
  
    const result: Packet[] = await invoke('get_sniffed_data');

    console.log(`Retrieved Network data sniffed: ${result}`);
  
    return result;
  }
}