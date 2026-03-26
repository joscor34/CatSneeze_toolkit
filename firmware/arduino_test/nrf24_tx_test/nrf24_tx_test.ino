/*
 * nRF24L01+ Enhanced ShockBurst — Sketch de prueba (Transmisor)
 * ==============================================================
 * Genera tráfico ESB real en el aire para que el sniffer CC1352P7
 * (con el firmware nrf24-sniffer) pueda capturarlo.
 *
 * Librería requerida: RF24 by TMRh20
 *   Arduino IDE → Administrador de bibliotecas → buscar "RF24"
 *
 * Conexión nRF24L01+ → Arduino Uno/Nano/Mega
 * ──────────────────────────────────────────
 *   VCC  → 3.3 V  (¡no 5V!)  +  condensador 100 µF entre VCC y GND
 *   GND  → GND
 *   CE   → Pin 9
 *   CSN  → Pin 10
 *   SCK  → Pin 13
 *   MOSI → Pin 11
 *   MISO → Pin 12
 *
 * Configuración Quick Start
 * ─────────────────────────
 *   Channel  : 76   (= 2476 MHz, mismo por defecto en el sniffer)
 *   Address  : E7E7E7E7E7
 *   Rate     : 1 Mbps
 *   PA Level : LOW  (laboratorio cercano)
 *
 * Modos de prueba (enviar por Serial Monitor a 115200 baud):
 *   'p'  → modo PERIODIC  — un paquete cada 500 ms (defecto)
 *   'b'  → modo BURST     — ráfaga de 10 paquetes rápidos
 *   'h'  → modo HID       — simula teclado inalámbrico (MouseJack)
 *   's'  → modo SENSOR    — envía valores de sensor simulados
 *   'm'  → modo MULTI     — rota entre 3 canales distintos
 *   '?'  → muestra estado actual
 */

#include <SPI.h>
#include <RF24.h>

// ── Pines ──────────────────────────────────────────────────────────────────────
#define CE_PIN   9
#define CSN_PIN  8

RF24 radio(CE_PIN, CSN_PIN);

// ── Configuración objetivos ────────────────────────────────────────────────────
const uint8_t DEFAULT_ADDR[5]    = {0xE7, 0xE7, 0xE7, 0xE7, 0xE7};
const uint8_t SECONDARY_ADDR[5]  = {0xC2, 0xC2, 0xC2, 0xC2, 0xC2};
const uint8_t CHANNEL_LIST[]     = {76, 2, 50};  // para modo MULTI
const uint8_t NUM_CHANNELS       = sizeof(CHANNEL_LIST);

// ── Estado global ──────────────────────────────────────────────────────────────
enum Mode { PERIODIC, BURST, HID, SENSOR, MULTI };
Mode currentMode = PERIODIC;

uint32_t pktCount    = 0;
uint32_t lastSend    = 0;
uint8_t  channelIdx  = 0;
uint8_t  pidCounter  = 0;  // PID rotativo 0-3 (2 bits ESB)

// ── Payload: HID Report (compatible MouseJack / Nordic nRF24 HID) ──────────────
// Formato HID de teclado USB estándar:
//   [modifier][reserved][key1][key2][key3][key4][key5][key6]
struct HIDReport {
    uint8_t modifier;   // 0x02 = Left Shift
    uint8_t reserved;
    uint8_t keys[6];
};

// Lookup table básica: 'H','O','L','A' → keycodes USB HID
// HID keycodes: a=0x04, b=0x05 … z=0x1D; espacio=0x2C
const uint8_t HID_SEQ[][2] = {
    {0x00, 0x0B},  // h
    {0x00, 0x12},  // o
    {0x00, 0x0F},  // l
    {0x00, 0x04},  // a (≈ 'a')
    {0x00, 0x2C},  // space
    {0x02, 0x16},  // S (Shift+s)
    {0x00, 0x12},  // o
    {0x02, 0x17},  // T (Shift+t)
    {0x00, 0x2C},  // space
    {0x00, 0x28},  // Enter
};
const uint8_t HID_SEQ_LEN = sizeof(HID_SEQ) / sizeof(HID_SEQ[0]);
uint8_t hidIdx = 0;

// ── Setup ──────────────────────────────────────────────────────────────────────
void setup() {
    Serial.begin(115200);
    Serial.println(F("[nRF24 TX Test] Iniciando…"));

    if (!radio.begin()) {
        Serial.println(F("[ERR] nRF24L01+ no encontrado. Revisa conexiones SPI."));
        while (true) delay(1000);
    }

    applyConfig(CHANNEL_LIST[0], DEFAULT_ADDR);

    Serial.println(F("[nRF24 TX Test] Listo."));
    printStatus();
    Serial.println(F("Comandos: p=PERIODIC b=BURST h=HID s=SENSOR m=MULTI ?=estado"));
}

// ── Loop ───────────────────────────────────────────────────────────────────────
void loop() {
    // Procesar comandos Serial
    if (Serial.available()) {
        char cmd = (char)Serial.read();
        handleCommand(cmd);
    }

    uint32_t now = millis();

    switch (currentMode) {
        case PERIODIC:
            if (now - lastSend >= 500) {
                sendGenericPacket();
                lastSend = now;
            }
            break;

        case BURST:
            // Ráfaga de 10 paquetes en < 10 ms, luego pausa 2 s
            for (uint8_t i = 0; i < 10; i++) {
                sendGenericPacket();
                delayMicroseconds(400);
            }
            Serial.print(F("[BURST] 10 pkts enviados. Total: "));
            Serial.println(pktCount);
            currentMode = PERIODIC;
            lastSend = millis();
            break;

        case HID:
            if (now - lastSend >= 80) {  // 80 ms entre teclas = ~12 tpm
                sendHIDPacket();
                lastSend = now;
            }
            break;

        case SENSOR:
            if (now - lastSend >= 1000) {
                sendSensorPacket();
                lastSend = now;
            }
            break;

        case MULTI:
            if (now - lastSend >= 300) {
                channelIdx = (channelIdx + 1) % NUM_CHANNELS;
                uint8_t ch = CHANNEL_LIST[channelIdx];
                radio.setChannel(ch);
                sendGenericPacket();
                lastSend = now;
            }
            break;
    }
}

// ── Helpers de envío ───────────────────────────────────────────────────────────

void sendGenericPacket() {
    // Payload: [pktCount 4B][timestamp 4B][relleno 0xAA]
    uint8_t payload[16];
    payload[0] = (pktCount >> 24) & 0xFF;
    payload[1] = (pktCount >> 16) & 0xFF;
    payload[2] = (pktCount >>  8) & 0xFF;
    payload[3] =  pktCount        & 0xFF;
    uint32_t t = millis();
    payload[4] = (t >> 24) & 0xFF;
    payload[5] = (t >> 16) & 0xFF;
    payload[6] = (t >>  8) & 0xFF;
    payload[7] =  t        & 0xFF;
    for (uint8_t i = 8; i < 16; i++) payload[i] = 0xAA;

    bool ok = radio.write(payload, sizeof(payload));
    pktCount++;

    // Imprimir línea de log compatible con el formato esperado por el sniffer
    // (para depuración local — el CC1352P7 real decodifica el frame RF)
    Serial.print(F("[TX] pkt="));
    Serial.print(pktCount);
    Serial.print(F(" ch="));
    Serial.print(CHANNEL_LIST[channelIdx]);
    Serial.print(F(" ok="));
    Serial.print(ok ? "1" : "0");
    Serial.print(F(" pld="));
    for (uint8_t i = 0; i < sizeof(payload); i++) {
        if (payload[i] < 0x10) Serial.print('0');
        Serial.print(payload[i], HEX);
    }
    Serial.println();
}

void sendHIDPacket() {
    HIDReport report;
    memset(&report, 0, sizeof(report));
    report.modifier = HID_SEQ[hidIdx][0];
    report.keys[0]  = HID_SEQ[hidIdx][1];

    bool ok = radio.write(&report, sizeof(report));
    pktCount++;
    hidIdx = (hidIdx + 1) % HID_SEQ_LEN;

    Serial.print(F("[HID] key=0x"));
    Serial.print(report.keys[0], HEX);
    Serial.print(F(" mod=0x"));
    Serial.print(report.modifier, HEX);
    Serial.print(F(" ok="));
    Serial.println(ok ? "1" : "0");
}

void sendSensorPacket() {
    // Simula lectura de temperatura + humedad (como un sensor inalámbrico)
    // [0xDE 0xAD][tipo=0x01][temp_hi][temp_lo][hum][bat][seq][0xFF]
    int16_t tempRaw = (int16_t)(2500 + (random(-300, 300)));  // 22-28 °C * 100
    uint8_t hum     = (uint8_t)(random(40, 80));
    uint8_t bat     = (uint8_t)(random(80, 100));
    static uint8_t seq = 0;

    uint8_t payload[8];
    payload[0] = 0xDE;
    payload[1] = 0xAD;
    payload[2] = 0x01;                          // tipo: temperatura/humedad
    payload[3] = (tempRaw >> 8) & 0xFF;
    payload[4] = tempRaw & 0xFF;
    payload[5] = hum;
    payload[6] = bat;
    payload[7] = seq++;

    bool ok = radio.write(payload, sizeof(payload));
    pktCount++;

    Serial.print(F("[SENSOR] temp="));
    Serial.print((float)tempRaw / 100.0, 1);
    Serial.print(F("°C hum="));
    Serial.print(hum);
    Serial.print(F("% bat="));
    Serial.print(bat);
    Serial.print(F("% ok="));
    Serial.println(ok ? "1" : "0");
}

// ── Configuración del radio ────────────────────────────────────────────────────

void applyConfig(uint8_t channel, const uint8_t* addr) {
    radio.stopListening();
    radio.setChannel(channel);
    radio.setDataRate(RF24_1MBPS);        // coincide con rate=1M del sniffer
    radio.setPALevel(RF24_PA_LOW);        // bajo para pruebas en banco
    radio.setPayloadSize(0);              // dynamic payload
    radio.enableDynamicPayloads();
    radio.setAutoAck(true);
    radio.setRetries(5, 15);             // 5 reintentos, 15*250µs = 3.75 ms delay
    radio.openWritingPipe(addr);
    radio.powerUp();

    Serial.print(F("[CFG] ch="));
    Serial.print(channel);
    Serial.print(F(" freq="));
    Serial.print(2400 + channel);
    Serial.print(F("MHz addr="));
    for (uint8_t i = 0; i < 5; i++) {
        if (addr[i] < 0x10) Serial.print('0');
        Serial.print(addr[i], HEX);
    }
    Serial.println();
}

// ── Comandos interactivos ──────────────────────────────────────────────────────

void handleCommand(char cmd) {
    switch (cmd) {
        case 'p':
            currentMode = PERIODIC;
            Serial.println(F("[CMD] modo → PERIODIC (500 ms)"));
            break;
        case 'b':
            currentMode = BURST;
            Serial.println(F("[CMD] modo → BURST (10 pkts)"));
            break;
        case 'h':
            currentMode = HID;
            hidIdx = 0;
            Serial.println(F("[CMD] modo → HID (simula teclado, cada 80 ms)"));
            break;
        case 's':
            currentMode = SENSOR;
            Serial.println(F("[CMD] modo → SENSOR (dato cada 1 s)"));
            break;
        case 'm':
            currentMode = MULTI;
            channelIdx = 0;
            applyConfig(CHANNEL_LIST[0], DEFAULT_ADDR);
            Serial.println(F("[CMD] modo → MULTI-CHANNEL (rota ch 76/2/50)"));
            break;
        case '2':
            applyConfig(CHANNEL_LIST[0], SECONDARY_ADDR);
            Serial.println(F("[CMD] addr → C2C2C2C2C2"));
            break;
        case '?':
            printStatus();
            break;
        case 'r':
            // Reset contador
            pktCount = 0;
            Serial.println(F("[CMD] contador reseteado"));
            break;
        default:
            break;
    }
}

void printStatus() {
    const char* modeNames[] = {"PERIODIC", "BURST", "HID", "SENSOR", "MULTI"};
    Serial.println(F("──────────────────────────────────────"));
    Serial.print(F("  Modo     : ")); Serial.println(modeNames[(int)currentMode]);
    Serial.print(F("  Canal    : ")); Serial.println((int)CHANNEL_LIST[channelIdx]);
    Serial.print(F("  Freq     : ")); Serial.print(2400 + CHANNEL_LIST[channelIdx]); Serial.println(F(" MHz"));
    Serial.print(F("  Rate     : RF24_1MBPS"));   Serial.println();
    Serial.print(F("  Addr     : E7E7E7E7E7 (default)"));  Serial.println();
    Serial.print(F("  Pkts TX  : ")); Serial.println(pktCount);
    Serial.println(F("──────────────────────────────────────"));
}
