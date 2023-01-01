# Rust Network Analyzer

> A simple Network Sniffer powered by <a href="https://tauri.app">Tauri</a>⚡. Embrace the power of <a href="https://www.rust-lang.org/">Rust</a>⚙️ while keeping a fresh look with <a hfref="https://vuejs.org/">Vue.js</a> 😼.

## Come funziona.

### Struttura del progetto.
Nella repository sono presenti due cartelle:
- `standalone_app`: Versione dell'applicazione solo con Rust. Contiene un main di prova per testare le funzionalità
- `network_analyzer`: Versione completa con Tauri. La sottocartella: `src-tauri` contiene lo stesso progetto rust presente in `standalone_app` 

### Prerequisiti
- [Node.js 16](https://nodejs.org/en/)
- [Yarn Package Manager](https://yarnpkg.com/)
- [Rust](https://www.rust-lang.org/tools/install) (Currently using version 1.66)

### Installare il progetto in Locale
Spostarsi nella directory con il progetto in tauri:
```bash
cd network_analyzer
```

Installare le dipendenze con yarn lanciando semplicemente:
```bash
yarn
```

e siete pronti a partire 🚀

### Lanciare il Progetto in Locale
Per lanciare il dev-server da locale con tauri lanciare il seguente comando:
```bash
cd network_analyzer
```

```bash
yarn tauri dev
```

### Buildare l'applicativo del progetto
Per buildare l'eseguibile dell'applicazione lanciare il seguente comando:

```bash
cd network_analyzer
```

```bash
yarn tauri build
```

oppure:
```bash
yarn tauri build --debug
```
per creare una build di debug che abbia un terminale associato con i vari log dell'applicazione.


Una volta terminata la compilazione l'installer dell'eseguibile sarà disponibile nella cartella:
`network_analyzer/src-tauri/target/release/bundle/`

oppure, in caso di debug build:
`network_analyzer/src-tauri/target/debug/bundle/`

## Caveats
Per ora lo sniffer funziona su windows solo se viene lanciato da una shell con permessi di amministratore.
