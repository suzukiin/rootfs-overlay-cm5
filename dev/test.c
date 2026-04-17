#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

// --- PROTÓTIPOS ---
char* read_file(const char* filename);
void process_amplifier(int amp_id, cJSON *amp_table);

// --- FUNÇÃO PARA LER O ARQUIVO JSON ---
char* read_file(const char* filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *data = malloc(len + 1);
    if (!data) {
        fclose(f);
        return NULL;
    }

    fread(data, 1, len, f);
    fclose(f);
    data[len] = '\0';
    return data;
}

// --- FUNÇÃO AGNÓSTICA PARA PROCESSAR UMA GAVETA ---
void process_amplifier(int amp_id, cJSON *amp_table) {
    if (!amp_table) return;

    const char *base_status_oid = cJSON_GetObjectItem(amp_table, "alerts_base_oid")->valuestring;
    cJSON *alerts_map = cJSON_GetObjectItem(amp_table, "alerts_map");
    cJSON *alert = NULL;

    printf("\n======================================\n");
    printf(" MONITORANDO GAVETA ID: %d\n", amp_id);
    printf("======================================\n");

    // Exemplo de leitura analógica (Temperatura)
    const char *temp_oid = cJSON_GetObjectItem(amp_table, "base_oid_temp")->valuestring;
    printf("[MEDIDA] Temperatura -> OID: %s.%d\n", temp_oid, amp_id);

    // Loop que percorre TODOS os alertas do JSON para esta gaveta
    printf("[STATUS] Varrendo alertas...\n");
    cJSON_ArrayForEach(alert, alerts_map) {
        int code = cJSON_GetObjectItem(alert, "code")->valueint;
        const char *label = cJSON_GetObjectItem(alert, "label")->valuestring;

        // Montagem da OID conforme manual R&S: BASE . ID_GAVETA . 1 . 1 . CODIGO
        // Ex: .1.3.6.1.4.1.2566.127.1.2.216.3.1.10.1.1.8 . 1 . 1.1 . 10000
        printf("  - %-18s | OID: %s.%d.1.1.%d\n", label, base_status_oid, amp_id, code);
    }
}

// --- FUNÇÃO PRINCIPAL ---
int main() {
    // 1. Carrega o conteúdo do arquivo
    char *json_raw = read_file("rs_xx9.json");
    if (!json_raw) {
        fprintf(stderr, "Erro: Nao foi possivel ler o arquivo rs_xx9.json\n");
        return 1;
    }

    // 2. Faz o Parse do JSON
    cJSON *root = cJSON_Parse(json_raw);
    if (!root) {
        fprintf(stderr, "Erro ao processar JSON: [%s]\n", cJSON_GetErrorPtr());
        free(json_raw);
        return 1;
    }

    printf("JUPITER Telemetry - Iniciando Teste de Template\n");
    printf("Fabricante: %s | Modelo: %s\n", 
            cJSON_GetObjectItem(root, "manufacturer")->valuestring,
            cJSON_GetObjectItem(root, "series")->valuestring);

    // 3. Simulação de Descoberta (Discovery)
    // No futuro, estes IDs virão de um snmp_walk real
    int discovery_list[] = {1, 2, 5}; // Ex: Transmissor com 3 gavetas nos slots 1, 2 e 5
    int total_found = 3;

    cJSON *amp_table = cJSON_GetObjectItem(root, "amplifier_table");

    // 4. Loop agnóstico: Processa cada gaveta encontrada
    for (int i = 0; i < total_found; i++) {
        process_amplifier(discovery_list[i], amp_table);
    }

    // 5. Limpeza
    printf("\nTeste concluido com sucesso.\n");
    cJSON_Delete(root);
    free(json_raw);

    return 0;
}