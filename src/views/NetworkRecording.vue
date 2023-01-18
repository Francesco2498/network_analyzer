<script setup lang="ts">
  import { ref, onMounted, Ref } from 'vue'
  import { Device } from '../models/network';
  import { Packet } from '../models/rust_structs';
  import { RecordingStatus } from '../models/commons';
  import {BackendAPI} from '../api';

  import PacketEntry from '../components/NetworkRecording/PacketEntry.vue';


  /*
   * REFS
   */
  const emit = defineEmits(['changeView']);

  // Current Device to analyze traffic from
  const device: Ref<Device | null> = ref(null);
  // Data Recorded
  const recordedData: Ref<Packet[]> = ref([]);
  // Path for the report
  const reportPath: Ref<string> = ref("./report.txt");
  // TimerID for the recording
  const timerId: Ref<NodeJS.Timer | null> = ref(null); 
  // Status of the application
  const status: Ref<RecordingStatus> = ref('IDLE');

  /**
   * HOOKS
   */ 
  onMounted(async () => {
    device.value = await BackendAPI.getDevice();
  })
  
  /*
   * METHODS
   */

  function getDeviceName() {
    const name = device.value?.name || '';
    if (name.length < 20) return name;
    // else
    return name.slice(0,30).concat('...');

  }

  async function updateRecordedData() {
    console.log(`Updating Data for timer ${timerId.value}`);
    recordedData.value = await BackendAPI.getNetworkData();
  }

  async function startRecording() {

    // Prevent multiple timers
    if (timerId.value !== null) return;

    console.log("Starting a new Recording");
    // update status
    status.value = 'REC';

    // Starting Backend Sniffer
    await BackendAPI.startOrResumeSniffer();

    // Start polling data from backend
    timerId.value = setInterval(() => {
      updateRecordedData();
    }, 1000);
  }

  async function pauseRecording() {
    // Assert that a timer is actually active
    if (timerId.value === null) return;
    
    // Stop Interval

    // update status
    status.value = 'PAUSED';

    console.log(`Canceling timer ${timerId.value}`);
    clearInterval(timerId.value);
    
    // reset timerId to null
    timerId.value = null;

    // Starting Backend Sniffer
    await BackendAPI.pauseSniffer();

    // cleanup recorded data
    recordedData.value = [];
  }

  async function goBackToSelection() {
    // First Stop Sniffer if active
    if (status.value !== 'IDLE'){
      await BackendAPI.stopSniffer();

      // Optionally clear timerId
      if (timerId.value !== null){
        clearInterval(timerId.value);
        timerId.value = null;
      }
    }
   
    // Change view
    emit('changeView', 1);
  }

  async function generateReport() {

    if (status.value !== 'PAUSED') return;

    // Starting Backend Sniffer
    await BackendAPI.generateReport(reportPath.value);

    // Set status to IDLE
    status.value = 'IDLE'
  }

</script>

<template>
  <div class="box">
    <header>
      <h2 class="title">Network Analysis</h2>
      <p class="descriptive">
        Listening on: <br/>
        <a class="clickable" @click="goBackToSelection">
          {{getDeviceName()}}
        </a>
      </p>
    </header>

    <div class="record-panel">
      
      <PacketEntry :is-header="true" />
      
      <div class="record-panel-body">
        <p v-if="recordedData.length === 0">
          Nothing to see here yet 🤫
        </p>
        <PacketEntry
          v-else
          v-for="record in recordedData"
        
          :packet="record"
        />
      </div>

    </div>

    <div 
      class="circle-button brown"
      :class="status === 'PAUSED' ? 'clickable': '' "
      @click="generateReport" 
    >
      <img src="../assets/download.png" alt="DLOAD" />
    </div>

    <div 
      class="circle-button blue"
      :class="status === 'REC' ? 'clickable': '' "
      @click="pauseRecording" 
    >
      <img src="../assets/pause.png" alt="PAUSE" />
    </div>

    <div 
      class="circle-button red"
      :class="status !== 'REC' ? 'clickable': '' "
      @click="startRecording" 
    >
      <img src="../assets/record.png" alt="REC" />
    </div>

  </div>
</template>

<style scoped>

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  header > h2 {
    font-size: 2em;
  }

  p.descriptive {
    text-align: left;
  }

  p > a.clickable:hover {
    cursor: pointer;
  }

  .record-panel {
    width: 80vw;
    padding: 1rem;
    box-shadow: 0px 0px 10px 2px #01101e82;
    border-radius: 10px;
  }

  .record-panel-body {
    height: 45vh;
    overflow-y: scroll;
    -ms-overflow-style: none;  /* IE and Edge */
    scrollbar-width: none;  /* Firefox */
  }
  
  .record-panel-body::-webkit-scrollbar {
    display: none;
  }

  .circle-button {
    width: 9vw;
    height: 9vw;
    background-color: #112132;
    border-radius: 100%;
    text-align: center;
    display: flex;
    align-items: center;
    justify-items: center;
    float: right;
    margin: auto 0.6rem;
    transition: 200ms;
    box-shadow: 2px 2px 10px 5px #01101e82;
  }

  .circle-button.clickable.red {
    background-color: #b43000;
  }

  .circle-button.clickable.blue {
    background-color: #003566;
  }

  .circle-button.clickable.brown {
    background-color: #442c11;
  }

  .circle-button.clickable:hover {
    transform: scale(1.1);
    cursor: pointer;
    box-shadow: 4px 6px 5px 5px #01101e82;
  }

  .circle-button img {
    width: 40%;
    margin: auto;
    filter: invert(0.5);
  }
  
  .circle-button.clickable img {
    filter: invert(1);
  }

  .circle-button h3 {
    margin: auto;
    font-size: 1.1em;
  }

</style>