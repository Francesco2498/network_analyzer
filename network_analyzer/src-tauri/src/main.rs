#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

use network_analyzer::frontend_api;

fn main() {
  tauri::Builder::default()
    .manage(frontend_api::SnifferState(Default::default()))
    .invoke_handler(tauri::generate_handler![
      frontend_api::get_all_devices, 
      frontend_api::set_device,
      frontend_api::get_device,
    ])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
