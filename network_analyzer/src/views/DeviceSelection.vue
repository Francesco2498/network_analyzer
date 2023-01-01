<script setup lang="ts">
  import { ref, onMounted, Ref } from 'vue'
  import DeviceEntry from '../components/DeviceSelection/DeviceEntry.vue';
  import { Device } from '../models/network';
  import {BackendAPI} from '../api';

  /*
   * REFS
   */
  const devices: Ref<Device[]> = ref([]);
  const selectedDevice:Ref<Device | null> = ref(null);

  const emit = defineEmits(['changeView']);


  // HOOKS
  onMounted(async () => {
    devices.value = await BackendAPI.getAllDevices();
  })
  
  /*
   * METHODS
   */
  function isSelected (device: Device): boolean {
    if (selectedDevice.value === null) return false;
    return selectedDevice.value.id === device.id;
  }

  function canProceed(): boolean {
    return (selectedDevice.value !== null);
  }

  async function confirmAndGoToRecordPage() {
    
    // Do nothing if no device is selected
    if (!selectedDevice.value) return;

    // Try to Set the device on the backend side
    try {
      await BackendAPI.setDevice(selectedDevice.value.id);
      
      // If Successfull go ahead to record page
      emit('changeView', 2);
    }
    catch (error) {
      // TODO Show error to frontend
      console.error(error);
    }
  }

</script>

<template>
  <div>
    <h2 class="title">Select the Network Device:</h2>

    <!-- DEVICES -->
    <div class="devices-panel">
      <div v-if="devices.length === 0" class="no-device">
        Could Not Find any Device 😿
      </div>
      <DeviceEntry
      class="device"
      v-else
      v-for="device in devices"
      :device="device"
      :isSelected="isSelected(device)"
      @click="()=>selectedDevice=device"
      >
        {{device.name}} | {{device.ipv4Address}}
      </DeviceEntry>
    
    </div>

    <!-- BUTTONS -->

    <div 
      class="ok-button" 
      :class="canProceed() ? 'clickable' : ''"

      @click="confirmAndGoToRecordPage"
    >
      <h2>GO</h2>
    </div>

  </div>
</template>

<style scoped>
  h2 {
    text-align: left;
    margin: 2rem auto;
  }

  .devices-panel {
    height: 50vh;
    overflow-y: scroll;
    padding: 2rem;
    box-shadow: 0px 0px 10px 2px #01101e82;
    border-radius: 10px;

    -ms-overflow-style: none;  /* IE and Edge */
    scrollbar-width: none;  /* Firefox */
  }
  .devices-panel::-webkit-scrollbar {
    display: none;
  }

  .device {
    margin: 0.5rem auto;
  }

  .no-device {
    width: 80vw;
    margin: 2rem auto;
    font-size: large;
    color: #6b798b;
  }

  .ok-button {
    width: 9vw;
    height: 9vw;
    background-color: #112132;
    border-radius: 100%;
    text-align: center;
    display: flex;
    align-items: center;
    justify-items: center;
    float: right;

    transition: 200ms;
    box-shadow: 2px 2px 10px 5px #01101e82;
  }

  .ok-button.clickable {
    background-color: #FFC300;
  }

  .ok-button.clickable:hover {
    transform: scale(1.1);
    cursor: pointer;
    box-shadow: 4px 6px 5px 5px #01101e82;
  }

  .ok-button h2 {
    margin: auto;
  }

</style>