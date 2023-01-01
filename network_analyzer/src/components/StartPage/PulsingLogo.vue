<template>
  <div class="box">
    <img src="../../assets/logo.png" alt="Logo" />
    <div class="circle"></div>
    <div class="shadow"></div>
  </div>
</template>

<style scoped>
  .box {
    position: relative;
    width: 180px;
    height: 180px;

    display: flex;
    align-items:center;
    justify-content: center; 
  
  }

  .circle {
    position: absolute;
    z-index: 1;
    width: 100%;
    height: 100%;
    border: 4px solid white;
    border-radius: 100%;
    box-shadow: 0 0 8px rgba(0,0,0,.3);
    animation: pulse-dot 2s cubic-bezier(0.455, 0.03, 0.515, 0.955) infinite;
  }

  .shadow {
    position: absolute;
    z-index: 0;
    width: 130%;
    height: 130%;
    box-sizing: border-box;
    border-radius: 100%;
    border: 15px solid #ffc300;
    animation: pulse-ring 2s cubic-bezier(0.215, 0.61, 0.355, 1) infinite;
  }

  img {
    z-index: 2;
    width: 60%;
  }

  @keyframes pulse-ring {
    0% {
      transform: scale(.7);
      border: 2px solid #ffc300;
    }
    80%, 100% {
      opacity: 0;
      border: 30px solid #ffc300;
    }
  }

  @keyframes pulse-dot {
    0% {
      transform: scale(.9);
    }
    50% {
      transform: scale(1);
    }
    100% {
      transform: scale(.9);
    }
  }
</style>