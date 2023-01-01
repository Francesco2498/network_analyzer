<script setup lang="ts">
  
  defineProps<{
    title: string
  }>()


</script>

<template>
  <button>
    {{title}}
  </button>
</template>

<style scoped>
  
  button {
    border-radius: 8px;
    border: 3px solid transparent;
    padding: 0.6em 1.2em;
    font-size: 1.2em;
    font-weight: 600;
    font-family: inherit;
    background-color: #003566;
    cursor: pointer;
    transition: 0.5s;
  }
  button:hover {
    border-color: #ffc300;
    background-color: transparent;
    color: #ffc300;
  }
  button:focus,
  button:focus-visible {
    outline: none;
  }

</style>