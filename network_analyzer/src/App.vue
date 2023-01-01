<script setup lang="ts">
  import DeviceSelection from './views/DeviceSelection.vue';
  import NetworkRecording from './views/NetworkRecording.vue';
  import StartPage from './views/StartPage.vue';

  import { ref, Ref } from 'vue'

  // PROPS
  const currentView: Ref<number> = ref(0);

  // METHODS
  function switchView(viewId: number) {
    currentView.value = viewId;
  }

</script>

<template>
  <div>
    
    <StartPage 
      v-if="currentView === 0"
      @changeView="(id: number) => switchView(id)"
    />

    <DeviceSelection 
      v-if="currentView === 1"
      @changeView="(id: number) => switchView(id)"
    />
    
    <NetworkRecording 
      v-if="currentView === 2"
      @changeView="(id: number) => switchView(id)"
    />
  </div>
</template>

