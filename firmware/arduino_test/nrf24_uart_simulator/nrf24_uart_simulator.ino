/*
 * Simulador UART del firmware CC1352P7 (nrf24-sniffer)
 * =====================================================
 * Emula por USB Serial el protocolo de texto que el firmware real enviaría,
 * permitiendo probar nrf24_sniffer.py SIN tener el hardware CC1352P7.
 *
 * Conecta el Arduino al PC y apunta el sniffer a su puerto COM/ttyUSB.
 *   Linux/Mac : python main.py → nrf24_sniffer → port=/dev/ttyUSB0
 *   Windows   : port=COM3  etc.
 *
 * Protocolo simulado (líneas que reconoce nrf24_sniffer.py):
 * ──────────────────────────────────────────────────────────
 *   [INIT] ch=076 freq=2476MHz rate=1M mode=promisc
 *   [CMD]  CH:076 OK
 *   [ESB]  ch=76 rssi=-65 addr=E7E7E7E7E7 plen=16 pid=0 noack=0 pld=DEADBEEF… crc=OK
 *   [ACK]  ch=76 rssi=-70 addr=E7E7E7E7E7 empty
 *   [SCAN] ch=076 active=1 pkts=5 rssi_max=-60
 *   [ERR]  mensaje de error
 *
 * Comandos que acepta (los mismos que enviaría nrf24_sniffer.py):
 *   CH:076       → fijar canal
 *   CH:SCAN      → activar modo SCAN
 *   RATE:1M      → fijar rate (reconocido, ignorado en simulación)
 *   ADDR:XXXXXXXX → fijar dirección objetivo (modo directed)
 *
 * Ajustes
 * ───────
 *   SIM_MODE    → "promisc" | "directed" | "scan"
 *   PKT_DELAY_MS→ ms entre paquetes simulados
 *   NUM_DEVICES → cuántos dispositivos ficticios hay en el "aire"
 */

// ── Configuración ──────────────────────────────────────────────────────────────
#define SIM_BAUD        115200
#define PKT_DELAY_MS    500        // intervalo entre frames [ESB]
#define ACK_EVERY       3          // enviar [ACK] cada N frames
#define NUM_DEVICES     3          // dispositivos ficticios
#define SCAN_INTERVAL   2000       // ms entre reportes [SCAN] en modo scan

// ── Dispositivos ficticios ──────────────────────────────────────────────────────
struct FakeDevice {
    const char* addr;
    uint8_t     channel;
    int8_t      rssi_base;   // RSSI base, varía ±5 dBm
    uint8_t     pid;         // PID ESB rotativo (0-3)
};

FakeDevice fakeDevs[NUM_DEVICES] = {
    {"E7E7E7E7E7",  76, -65, 0},   // dirección por defecto del sniffer
    {"A5A5A5A5A5",   2, -80, 0},   // segundo device en canal 2
    {"C2C2C2C2C2",  50, -72, 0},   // tercero en canal 50
};

// ── Estado global ──────────────────────────────────────────────────────────────
char    simMode[16]    = "promisc";
uint8_t currentChannel = 76;
char    targetAddr[12] = "E7E7E7E7E7";
bool    scanMode       = false;

uint32_t lastPkt    = 0;
uint32_t lastScan   = 0;
uint32_t pktTotal   = 0;
uint8_t  ackCounter = 0;
uint8_t  devIdx     = 0;     // dispositivo actual en rotación

char    cmdBuf[64];
uint8_t cmdLen = 0;

// ── Payloads de ejemplo ────────────────────────────────────────────────────────
// Cada uno es una cadena HEX de hasta 32 bytes (64 chars)
const char* SAMPLE_PAYLOADS[] = {
    "DEADBEEF0102030405060708",         // genérico
    "00000000000000000000000000000000", // todos ceros
    "0116000000000000",                 // HID report (Logitech estilo)
    "AA55AA55AA55AA55",                 // patrón alterno
    "DE01271A4F64AB",                   // sensor temperatura (ver tx_test)
    "FF0102030405060708090A0B0C0D0E0F", // relleno incremental
    "48454C4C4F",                       // "HELLO" en ASCII
    "",                                 // payload vacío (solo encabezado)
};
const uint8_t NUM_PAYLOADS = sizeof(SAMPLE_PAYLOADS) / sizeof(SAMPLE_PAYLOADS[0]);
uint8_t pldIdx = 0;

// ── Setup ──────────────────────────────────────────────────────────────────────
void setup() {
    Serial.begin(SIM_BAUD);
    delay(500);

    // Mensaje de inicio (coincide con _INIT_RE del sniffer Python)
    Serial.print(F("[INIT] ch="));
    printChannelPadded(currentChannel);
    Serial.print(F(" freq="));
    Serial.print(2400 + currentChannel);
    Serial.print(F("MHz rate=1M mode="));
    Serial.println(simMode);

    Serial.println(F("[CMD] simulator ready"));
}

// ── Loop ───────────────────────────────────────────────────────────────────────
void loop() {
    // 1. Procesar comandos entrantes del sniffer Python
    while (Serial.available()) {
        char c = (char)Serial.read();
        if (c == '\n' || c == '\r') {
            cmdBuf[cmdLen] = '\0';
            if (cmdLen > 0) processCommand(cmdBuf);
            cmdLen = 0;
        } else if (cmdLen < sizeof(cmdBuf) - 1) {
            cmdBuf[cmdLen++] = c;
        }
    }

    uint32_t now = millis();

    // 2. En modo SCAN emitir reportes [SCAN]
    if (scanMode && (now - lastScan >= SCAN_INTERVAL)) {
        emitScanResults();
        lastScan = now;
    }

    // 3. Emitir frames ESB simulados
    if (!scanMode && (now - lastPkt >= PKT_DELAY_MS)) {
        emitESBFrame();
        lastPkt = now;
    }

    // En modo scan también emitir tramas esporádicas en canales activos
    if (scanMode && (now - lastPkt >= PKT_DELAY_MS * 2)) {
        emitESBFrame();
        lastPkt = now;
    }
}

// ── Emitir frame [ESB] ─────────────────────────────────────────────────────────
void emitESBFrame() {
    FakeDevice& dev = fakeDevs[devIdx % NUM_DEVICES];
    devIdx++;

    // Variar RSSI de forma pseudoaleatoria
    int8_t rssi = dev.rssi_base + (int8_t)(random(-5, 6));

    // PID rotativo 0-3 (2 bits ESB)
    dev.pid = (dev.pid + 1) & 0x03;

    // Seleccionar payload de muestra
    const char* pld = SAMPLE_PAYLOADS[pldIdx % NUM_PAYLOADS];
    pldIdx++;
    uint8_t plen = strlen(pld) / 2;  // bytes = chars hex / 2

    // noack: 1 de cada 5 es NO_ACK
    uint8_t noack = (pktTotal % 5 == 0) ? 1 : 0;
    pktTotal++;

    // [ESB] ch=76 rssi=-65 addr=E7E7E7E7E7 plen=12 pid=1 noack=0 pld=DEAD… crc=OK
    Serial.print(F("[ESB] ch="));
    Serial.print(dev.channel);
    Serial.print(F(" rssi="));
    Serial.print(rssi);
    Serial.print(F(" addr="));
    Serial.print(dev.addr);
    Serial.print(F(" plen="));
    Serial.print(plen);
    Serial.print(F(" pid="));
    Serial.print(dev.pid);
    Serial.print(F(" noack="));
    Serial.print(noack);
    Serial.print(F(" pld="));
    Serial.print(pld);
    Serial.print(F(" crc="));
    // Simular CRC correcto el 95% de las veces
    Serial.println((random(100) < 95) ? "OK" : "FAIL");

    // Emitir [ACK] de vuelta ocasionalmente
    ackCounter++;
    if (ackCounter >= ACK_EVERY) {
        ackCounter = 0;
        emitACK(dev);
    }
}

// ── Emitir frame [ACK] ─────────────────────────────────────────────────────────
void emitACK(const FakeDevice& dev) {
    int8_t rssi = dev.rssi_base + (int8_t)(random(-3, 4));
    // [ACK] ch=76 rssi=-68 addr=E7E7E7E7E7 empty
    Serial.print(F("[ACK] ch="));
    Serial.print(dev.channel);
    Serial.print(F(" rssi="));
    Serial.print(rssi);
    Serial.print(F(" addr="));
    Serial.print(dev.addr);
    Serial.println(F(" empty"));
}

// ── Emitir resultados [SCAN] ───────────────────────────────────────────────────
void emitScanResults() {
    for (uint8_t i = 0; i < NUM_DEVICES; i++) {
        uint8_t pkts     = random(1, 20);
        int8_t  rssiMax  = fakeDevs[i].rssi_base + (int8_t)(random(0, 5));
        // [SCAN] ch=076 active=1 pkts=8 rssi_max=-62
        Serial.print(F("[SCAN] ch="));
        printChannelPadded(fakeDevs[i].channel);
        Serial.print(F(" active=1 pkts="));
        Serial.print(pkts);
        Serial.print(F(" rssi_max="));
        Serial.println(rssiMax);
    }
    // Canal inactivo (relleno)
    Serial.println(F("[SCAN] ch=100 active=0 pkts=0 rssi_max=-120"));
}

// ── Procesar comandos del sniffer Python ───────────────────────────────────────
void processCommand(const char* cmd) {
    // CH:076  o  CH:SCAN
    if (strncmp(cmd, "CH:", 3) == 0) {
        const char* val = cmd + 3;
        if (strcmp(val, "SCAN") == 0) {
            scanMode = true;
            strncpy(simMode, "scan", sizeof(simMode));
            Serial.println(F("[CMD] CH:SCAN OK mode=scan"));
            lastScan = millis() - SCAN_INTERVAL;  // emitir de inmediato
        } else {
            int ch = atoi(val);
            if (ch >= 0 && ch <= 125) {
                currentChannel = (uint8_t)ch;
                fakeDevs[0].channel = currentChannel;  // ajustar dispositivo 0
                scanMode = false;
                Serial.print(F("[CMD] CH:"));
                printChannelPadded(currentChannel);
                Serial.print(F(" OK freq="));
                Serial.print(2400 + currentChannel);
                Serial.println(F("MHz"));
            } else {
                Serial.println(F("[ERR] canal fuera de rango 0-125"));
            }
        }
        return;
    }

    // RATE:1M / RATE:2M / RATE:250K
    if (strncmp(cmd, "RATE:", 5) == 0) {
        Serial.print(F("[CMD] RATE:"));
        Serial.print(cmd + 5);
        Serial.println(F(" OK"));
        return;
    }

    // ADDR:E7E7E7E7E7
    if (strncmp(cmd, "ADDR:", 5) == 0) {
        strncpy(targetAddr, cmd + 5, sizeof(targetAddr) - 1);
        strncpy(simMode, "directed", sizeof(simMode));
        scanMode = false;
        // Forzar que el primer device use esta dirección
        fakeDevs[0].addr = targetAddr;
        Serial.print(F("[CMD] ADDR:"));
        Serial.print(targetAddr);
        Serial.println(F(" OK mode=directed"));
        return;
    }

    // Comando desconocido
    Serial.print(F("[ERR] cmd desconocido: "));
    Serial.println(cmd);
}

// ── Helper: imprimir canal con padding de 3 dígitos ───────────────────────────
void printChannelPadded(uint8_t ch) {
    if (ch < 10)  Serial.print('0');
    if (ch < 100) Serial.print('0');
    Serial.print(ch);
}
