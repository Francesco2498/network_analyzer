<script setup lang="ts">
  import { Device } from '../../models/network';

  defineProps<{
    device: Device,
    isSelected: boolean
  }>()


</script>

<template>
  <div class="panel" :class="isSelected ? 'selected' : ''">
    
    <img src="../../assets/device.png" alt="Device" />
    
    <h3 class="device-name">{{device.name}}</h3>
    
    <div class="addresses">
      <h4 class="address">ipv4: <strong>{{device.ipv4Address}}</strong></h4>
      <h4>netmask: <strong>{{device.netmask}}</strong></h4>
    </div>

  </div>
</template>

<style scoped>
  .panel {
    height: 13vh;
    width: 80vw;
    margin: .2rem;

    background-color: #003566;
    border-radius: 10px;

    display: grid;
    grid-template-columns: 20vw 30vw 30vw;
    grid-template-rows: 13vh;
    column-gap: 1vw;
  }

  .selected {
    border: 2px solid #FFC300;
    color: #FFC300
  }

  .panel:hover {
    cursor: pointer;
  }

  img {
    width: 8vw;
    justify-self: center;
    align-self: center;
  }

  .device-name {
    justify-self: left;
    align-self: center;
    margin: 0;
  }

  .addresses {
    justify-self: center;
    align-self: center;
    text-align: left;
  }
  
  .addresses h4 {
    font-weight: 300;
  }

</style>