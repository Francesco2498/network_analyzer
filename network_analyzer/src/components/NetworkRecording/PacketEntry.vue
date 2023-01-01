<script setup lang="ts">
  import { Packet } from '../../models/rust_structs';

  defineProps<{
    packet?: Packet,
    isHeader?: boolean
  }>()


  /**
   *  METHODS
   */
  function computeDirection(direction?: string): string {
    let imageName: string = 'device';
    if (direction === 'Received') imageName = 'down-arrow';
    else if (direction === 'Transmitted') imageName = 'up-arrow';
    
    return new URL(`../../assets/${imageName}.png`, import.meta.url).href;
  }

  function parseTime(time?: String) {
    if(!time) return '00:00:00';

    else return time.split('.')[0];
  }

</script>

<template>
  <div class="entry" :class="isHeader ? 'header' : 'record'">
    <p>
      {{isHeader ? 'Ip Address' : packet?.address}}
    </p>
    <p>
      {{isHeader ? 'Port' : packet?.port}}
    </p>
    <p>
      {{isHeader ? 'Protocol' : packet?.protocol}}
    </p>
    <p v-if="isHeader">
      Direction
    </p>
    <img 
      v-else
      :src="computeDirection(packet?.direction)"
    />
    <p>
      {{isHeader ? 'Bytes TX' : packet?.bytes_tx}}
    </p>
    <p>
      {{isHeader ? 'Start' : parseTime(packet?.start)}}
    </p>
    <p>
      {{isHeader ? 'End' : parseTime(packet?.end)}}
    </p>
  </div>
</template>

<style scoped>
  .entry {
    display: grid;
    grid-template-columns: 2fr 0.5fr 1fr 0.5fr 1fr 0.5fr 0.5fr;
  }

  .entry.record p{
    font-weight: 200;
    font-size: 12px;
  }

  .entry.header {
    font-weight: 600;
    color: #ffc300;
    border-bottom: 2px solid #ffc300;
  }

  img {
    justify-self: center;
    align-self: center;
    width: 18px;
  }

</style>
