/*
 * nRF24L01+ — Emisor (Transmisor) para Arduino Nano
 * ===================================================
 * Envía paquetes periódicos al receptor por Enhanced ShockBurst.
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
 * Configuración
 * ─────────────
 *   Canal    : 76 (2476 MHz)
 *   Dirección: E7E7E7E7E7
 *   Rate     : 1 Mbps
 *   PA Level : LOW (pruebas de banco)
 *
 * Modos (enviar por Serial Monitor a 115200 baud):
 *   '1' → Envío cada 500 ms (por defecto)
 *   '2' → Envío cada 100 ms
 *   '3' → Ráfaga de 20 paquetes
 *   '?' → Estado actual
 *   'r' → Resetear contador
 */

#include <SPI.h>
#include <RF24.h>

// ── Pines ──────────────────────────────────────────────────────────────────────
#define CE_PIN   9
#define CSN_PIN  8

RF24 radio(CE_PIN, CSN_PIN);

// ── Configuración ──────────────────────────────────────────────────────────────
const uint8_t PIPE_ADDR[5] = {0xE7, 0xE7, 0xE7, 0xE7, 0xE7};
const uint8_t CHANNEL      = 76;

// ── Estado ─────────────────────────────────────────────────────────────────────
uint32_t pktCount    = 0;
uint32_t okCount     = 0;
uint32_t failCount   = 0;
uint32_t lastSend    = 0;
uint16_t interval    = 500;  // ms entre envíos

// ── Estructura del paquete ─────────────────────────────────────────────────────
struct Packet {
    uint32_t id;         // número de paquete
    uint32_t timestamp;  // millis() al momento de enviar
    int16_t  value1;     // dato simulado (ej: temperatura * 100)
    int16_t  value2;     // dato simulado (ej: humedad * 10)
    uint8_t  flags;      // byte de flags genérico
    uint8_t  padding[3]; // relleno hasta 16 bytes
};

void setup() {
    Serial.begin(115200);
    Serial.println(F("═══════════════════════════════════"));
    Serial.println(F("  nRF24 EMISOR — Arduino Nano"));
    Serial.println(F("═══════════════════════════════════"));

    if (!radio.begin()) {
        Serial.println(F("[ERR] nRF24L01+ no detectado. Revisa SPI."));
        while (true) delay(1000);
    }

    radio.setChannel(CHANNEL);
    radio.setDataRate(RF24_1MBPS);
    radio.setPALevel(RF24_PA_LOW);
    radio.enableDynamicPayloads();     // necesario para que el sniffer CC1352P7 parsee plen correctamente
    radio.setAutoAck(false);           // sniffer pasivo no envía ACKs
    radio.setRetries(0, 0);            // sin reintentos: TX limpio sin duplicados
    radio.openWritingPipe(PIPE_ADDR);
    radio.stopListening();

    Serial.print(F("[TX] Canal: "));
    Serial.print(CHANNEL);
    Serial.print(F("  Freq: "));
    Serial.print(2400 + CHANNEL);
    Serial.println(F(" MHz"));
    Serial.println(F("[TX] Listo. Comandos: 1=500ms 2=100ms 3=burst ?=estado r=reset"));
    Serial.println();
}

void loop() {
    if (Serial.available()) {
        char cmd = (char)Serial.read();
        switch (cmd) {
            case '1':
                interval = 500;
                Serial.println(F("[CMD] Intervalo → 500 ms"));
                break;
            case '2':
                interval = 100;
                Serial.println(F("[CMD] Intervalo → 100 ms"));
                break;
            case '3':
                Serial.println(F("[CMD] Ráfaga de 20 paquetes..."));
                for (uint8_t i = 0; i < 20; i++) {
                    sendPacket();
                    delay(5);
                }
                Serial.println(F("[CMD] Ráfaga completada."));
                break;
            case 'r':
                pktCount = okCount = failCount = 0;
                Serial.println(F("[CMD] Contadores reseteados."));
                break;
            case '?':
                printStatus();
                break;
            default:
                break;
        }
    }

    uint32_t now = millis();
    if (now - lastSend >= interval) {
        sendPacket();
        lastSend = now;
    }
}

void sendPacket() {
    Packet pkt;
    pkt.id        = pktCount;
    pkt.timestamp = millis();
    pkt.value1    = (int16_t)(2200 + random(-200, 200));   // simula temp 20.0–24.0 °C
    pkt.value2    = (int16_t)(500 + random(-50, 50));       // simula hum 45.0–55.0 %
    pkt.flags     = pktCount & 0xFF;
    memset(pkt.padding, 0xAA, sizeof(pkt.padding));

    bool ok = radio.write(&pkt, sizeof(pkt));
    pktCount++;

    if (ok) {
        okCount++;
    } else {
        failCount++;
    }

    Serial.print(F("[TX] #"));
    Serial.print(pktCount);
    Serial.print(ok ? F(" OK") : F(" FAIL"));
    Serial.print(F("  val1="));
    Serial.print(pkt.value1);
    Serial.print(F("  val2="));
    Serial.print(pkt.value2);
    Serial.println();
}

void printStatus() {
    Serial.println(F("──────────────────────────────────"));
    Serial.print(F("  Intervalo : ")); Serial.print(interval); Serial.println(F(" ms"));
    Serial.print(F("  Canal     : ")); Serial.print(CHANNEL);
    Serial.print(F(" (")); Serial.print(2400 + CHANNEL); Serial.println(F(" MHz)"));
    Serial.print(F("  Enviados  : ")); Serial.println(pktCount);
    Serial.print(F("  OK        : ")); Serial.println(okCount);
    Serial.print(F("  FAIL      : ")); Serial.println(failCount);
    if (pktCount > 0) {
        Serial.print(F("  Éxito     : "));
        Serial.print((float)okCount * 100.0 / pktCount, 1);
        Serial.println(F(" %"));
    }
    Serial.println(F("──────────────────────────────────"));
}
