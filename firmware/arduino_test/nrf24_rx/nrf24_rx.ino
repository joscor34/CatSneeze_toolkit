/*
 * nRF24L01+ — Receptor para Arduino Nano
 * ========================================
 * Recibe paquetes Enhanced ShockBurst del emisor (nrf24_tx.ino)
 * y muestra los datos decodificados por Serial.
 *
 * Librería requerida: RF24 by TMRh20
 *   Arduino IDE → Administrador de bibliotecas → buscar "RF24"
 *
 * Conexión nRF24L01+ → Arduino Nano
 * ──────────────────────────────────
 *   VCC  → 3.3 V  (¡NO 5V!)  + condensador 100 µF entre VCC y GND
 *   GND  → GND
 *   CE   → Pin 9
 *   CSN  → Pin 8
 *   SCK  → Pin 13
 *   MOSI → Pin 11
 *   MISO → Pin 12
 *
 * Configuración (debe coincidir con el emisor)
 * ─────────────────────────────────────────────
 *   Canal    : 76 (2476 MHz)
 *   Dirección: E7E7E7E7E7
 *   Rate     : 1 Mbps
 *
 * Modos (enviar por Serial Monitor a 115200 baud):
 *   'd' → Detalle completo de cada paquete (por defecto)
 *   's' → Resumen: solo 1 línea por paquete
 *   'x' → Volcado hexadecimal raw
 *   '?' → Estado y estadísticas
 *   'r' → Resetear contadores
 */

#include <SPI.h>
#include <RF24.h>

// ── Pines ──────────────────────────────────────────────────────────────────────
#define CE_PIN   9
#define CSN_PIN  8

RF24 radio(CE_PIN, CSN_PIN);

// ── Configuración (DEBE coincidir con el emisor) ──────────────────────────────
const uint8_t PIPE_ADDR[5] = {0xE7, 0xE7, 0xE7, 0xE7, 0xE7};
const uint8_t CHANNEL      = 76;

// ── Estructura del paquete (idéntica al emisor) ────────────────────────────────
struct Packet {
    uint32_t id;
    uint32_t timestamp;
    int16_t  value1;
    int16_t  value2;
    uint8_t  flags;
    uint8_t  padding[3];
};

// ── Estado ─────────────────────────────────────────────────────────────────────
enum DisplayMode { DETAIL, SUMMARY, HEXDUMP };
DisplayMode displayMode = DETAIL;

uint32_t rxCount       = 0;
uint32_t lastPktId     = 0;
uint32_t lostCount     = 0;
uint32_t lastStatTime  = 0;
uint32_t rxLastSecond  = 0;
uint32_t rxPerSecond   = 0;

void setup() {
    Serial.begin(115200);
    Serial.println(F("═══════════════════════════════════"));
    Serial.println(F("  nRF24 RECEPTOR — Arduino Nano"));
    Serial.println(F("═══════════════════════════════════"));

    if (!radio.begin()) {
        Serial.println(F("[ERR] nRF24L01+ no detectado. Revisa SPI."));
        while (true) delay(1000);
    }

    radio.setChannel(CHANNEL);
    radio.setDataRate(RF24_1MBPS);
    radio.setPALevel(RF24_PA_LOW);
    radio.enableDynamicPayloads();     // coincide con el emisor y el sniffer CC1352P7
    radio.setAutoAck(false);           // coincide con el emisor
    radio.openReadingPipe(1, PIPE_ADDR);
    radio.startListening();

    Serial.print(F("[RX] Canal: "));
    Serial.print(CHANNEL);
    Serial.print(F("  Freq: "));
    Serial.print(2400 + CHANNEL);
    Serial.println(F(" MHz"));
    Serial.println(F("[RX] Escuchando... Comandos: d=detalle s=resumen x=hex ?=estado r=reset"));
    Serial.println();
}

void loop() {
    // Procesar comandos Serial
    if (Serial.available()) {
        char cmd = (char)Serial.read();
        switch (cmd) {
            case 'd':
                displayMode = DETAIL;
                Serial.println(F("[CMD] Modo → DETALLE"));
                break;
            case 's':
                displayMode = SUMMARY;
                Serial.println(F("[CMD] Modo → RESUMEN"));
                break;
            case 'x':
                displayMode = HEXDUMP;
                Serial.println(F("[CMD] Modo → HEXDUMP"));
                break;
            case 'r':
                rxCount = lostCount = rxLastSecond = rxPerSecond = 0;
                lastPktId = 0;
                Serial.println(F("[CMD] Contadores reseteados."));
                break;
            case '?':
                printStatus();
                break;
            default:
                break;
        }
    }

    // Calcular paquetes por segundo cada 1 s
    uint32_t now = millis();
    if (now - lastStatTime >= 1000) {
        rxPerSecond  = rxLastSecond;
        rxLastSecond = 0;
        lastStatTime = now;
    }

    // Recibir paquetes
    if (radio.available()) {
        uint8_t rawBuf[32];
        uint8_t len = radio.getDynamicPayloadSize();
        if (len > 32) return;  // payload inválido
        radio.read(rawBuf, len);
        rxCount++;
        rxLastSecond++;

        Packet pkt;
        memcpy(&pkt, rawBuf, sizeof(pkt));

        // Detectar paquetes perdidos
        if (rxCount > 1) {
            uint32_t expected = lastPktId + 1;
            if (pkt.id > expected) {
                uint32_t lost = pkt.id - expected;
                lostCount += lost;
                if (displayMode == DETAIL) {
                    Serial.print(F("[RX] ⚠ "));
                    Serial.print(lost);
                    Serial.println(F(" paquete(s) perdido(s)"));
                }
            }
        }
        lastPktId = pkt.id;

        // Mostrar según modo
        switch (displayMode) {
            case DETAIL:
                printDetail(pkt);
                break;
            case SUMMARY:
                printSummary(pkt);
                break;
            case HEXDUMP:
                printHex(rawBuf, sizeof(rawBuf));
                break;
        }
    }
}

// ── Modos de visualización ─────────────────────────────────────────────────────

void printDetail(const Packet& pkt) {
    Serial.println(F("┌─────────────────────────────────┐"));
    Serial.print(F("│ Paquete #"));
    Serial.println(pkt.id);
    Serial.print(F("│ Timestamp : "));
    Serial.print(pkt.timestamp);
    Serial.println(F(" ms"));
    Serial.print(F("│ Valor 1   : "));
    Serial.print((float)pkt.value1 / 100.0, 2);
    Serial.println(F(" (temp °C)"));
    Serial.print(F("│ Valor 2   : "));
    Serial.print((float)pkt.value2 / 10.0, 1);
    Serial.println(F(" (hum %)"));
    Serial.print(F("│ Flags     : 0x"));
    if (pkt.flags < 0x10) Serial.print('0');
    Serial.println(pkt.flags, HEX);
    Serial.print(F("│ Latencia  : "));
    Serial.print(millis() - pkt.timestamp);
    Serial.println(F(" ms (aprox)"));
    Serial.println(F("└─────────────────────────────────┘"));
}

void printSummary(const Packet& pkt) {
    Serial.print(F("[RX] #"));
    Serial.print(pkt.id);
    Serial.print(F("  v1="));
    Serial.print(pkt.value1);
    Serial.print(F("  v2="));
    Serial.print(pkt.value2);
    Serial.print(F("  lat="));
    Serial.print(millis() - pkt.timestamp);
    Serial.println(F("ms"));
}

void printHex(const uint8_t* buf, uint8_t len) {
    Serial.print(F("[HEX] "));
    for (uint8_t i = 0; i < len; i++) {
        if (buf[i] < 0x10) Serial.print('0');
        Serial.print(buf[i], HEX);
        if (i < len - 1) Serial.print(' ');
    }
    Serial.println();
}

// ── Estadísticas ───────────────────────────────────────────────────────────────

void printStatus() {
    Serial.println(F("──────────────────────────────────"));
    Serial.print(F("  Canal       : ")); Serial.print(CHANNEL);
    Serial.print(F(" (")); Serial.print(2400 + CHANNEL); Serial.println(F(" MHz)"));
    Serial.print(F("  Recibidos   : ")); Serial.println(rxCount);
    Serial.print(F("  Perdidos    : ")); Serial.println(lostCount);
    if (rxCount + lostCount > 0) {
        Serial.print(F("  Fiabilidad  : "));
        Serial.print((float)rxCount * 100.0 / (rxCount + lostCount), 1);
        Serial.println(F(" %"));
    }
    Serial.print(F("  Último ID   : ")); Serial.println(lastPktId);
    Serial.print(F("  Pkt/s       : ")); Serial.println(rxPerSecond);
    const char* modeNames[] = {"DETALLE", "RESUMEN", "HEXDUMP"};
    Serial.print(F("  Display     : ")); Serial.println(modeNames[(int)displayMode]);
    Serial.println(F("──────────────────────────────────"));
}
