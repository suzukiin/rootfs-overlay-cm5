#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

// --- PROTÓTIPOS ---
char* read_file(const char* filename);
void init_snmp_session(const char *ip);
int discover_amplifiers(const char *base_oid_str, int *found_ids);
int get_snmp_int(const char *oid_str);
const char* translate_status(int val);
void process_amplifier(int amp_id, cJSON *amp_table);

// --- GLOBAIS ---
struct snmp_session session, *ss;

// --- TRADUTOR DE STATUS (Conforme seu documento R&S) ---
const char* translate_status(int val) {
    switch(val) {
        case 2: return "OFF/NORMAL";
        case 3: return "FAULT";
        case 4: return "WARNING";
        case 5: return "OK/ON";
        case -1: return "TIMEOUT/NETWORK ERROR";
        case -2: return "OID NOT FOUND (INDEX ERROR)";
        default: return "UNDEFINED";
    }
}

// --- LEITURA DE ARQUIVO ---
char* read_file(const char* filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *data = malloc(len + 1);
    if (data) {
        size_t read_bytes = fread(data, 1, len, f);
        data[read_bytes] = '\0';
    }
    fclose(f);
    return data;
}

// --- INICIALIZAÇÃO SNMP ---
void init_snmp_session(const char *ip) {
    init_snmp("jupiter_telemetry");
    snmp_sess_init(&session);
    session.peername = strdup(ip);
    session.version = SNMP_VERSION_2c;
    session.community = (u_char *)"public";
    session.community_len = strlen((const char *)session.community);
    session.timeout = 1000000; // 1 segundo
    session.retries = 1;

    ss = snmp_open(&session);
    if (!ss) {
        snmp_sess_perror("Erro Crítico SNMP", &session);
        exit(1);
    }
}

// --- DESCOBERTA DE GAVETAS ---
int discover_amplifiers(const char *base_oid_str, int *found_ids) {
    struct snmp_pdu *pdu, *response;
    oid root_oid[MAX_OID_LEN], current_oid[MAX_OID_LEN];
    size_t root_oid_len, current_oid_len;
    int count = 0;

    if (!snmp_parse_oid(base_oid_str, root_oid, &root_oid_len)) return 0;
    memcpy(current_oid, root_oid, root_oid_len * sizeof(oid));
    current_oid_len = root_oid_len;

    while (count < 32) {
        pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
        snmp_add_null_var(pdu, current_oid, current_oid_len);
        
        int status = snmp_synch_response(ss, pdu, &response);
        if (status == STAT_SUCCESS && response && response->errstat == SNMP_ERR_NOERROR) {
            struct variable_list *vars = response->variables;
            if (vars && snmp_oid_compare(root_oid, root_oid_len, vars->name, root_oid_len) == 0) {
                int id = vars->name[vars->name_length - 1];
                found_ids[count++] = id;
                memcpy(current_oid, vars->name, vars->name_length * sizeof(oid));
                current_oid_len = vars->name_length;
            } else {
                if (response) snmp_free_pdu(response);
                break;
            }
        } else {
            if (response) snmp_free_pdu(response);
            break;
        }
        if (response) snmp_free_pdu(response);
    }
    return count;
}

// --- BUSCA VALOR (BLINDADA) ---
int get_snmp_int(const char *oid_str) {
    struct snmp_pdu *pdu, *response = NULL;
    oid an_oid[MAX_OID_LEN];
    size_t an_oid_len = MAX_OID_LEN;
    int val = -1;

    if (!snmp_parse_oid(oid_str, an_oid, &an_oid_len)) return -1;

    pdu = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, an_oid, an_oid_len);

    int status = snmp_synch_response(ss, pdu, &response);

    if (status == STAT_SUCCESS && response != NULL) {
        if (response->errstat == SNMP_ERR_NOERROR && response->variables != NULL) {
            u_char type = response->variables->type;
            // Se o tipo for 0x81 ou 0x80, é um erro de "No Such Instance"
            if (type == ASN_INTEGER || type == ASN_GAUGE || type == ASN_COUNTER) {
                val = (int)*response->variables->val.integer;
            } else {
                val = -2; // Erro de instância/tipo
            }
        }
    }

    if (response) snmp_free_pdu(response);
    return val;
}

// --- PROCESSA GAVETA (CORREÇÃO DE ÍNDICE) ---
void process_amplifier(int amp_id, cJSON *amp_table) {
    const char *base_status_oid = cJSON_GetObjectItem(amp_table, "alerts_base_oid")->valuestring;
    const char *base_temp_oid = cJSON_GetObjectItem(amp_table, "base_oid_temp")->valuestring;
    cJSON *alerts_map = cJSON_GetObjectItem(amp_table, "alerts_map");
    cJSON *alert = NULL;

    printf("\n>>> ANALISANDO GAVETA ID: %d\n", amp_id);

    // 1. Leitura de Temperatura (Agnóstica)
    char temp_oid_full[256];
    snprintf(temp_oid_full, sizeof(temp_oid_full), "%s.%d", base_temp_oid, amp_id);
    int temp = get_snmp_int(temp_oid_full);
    printf("  [MEDIDA] Temperatura: %d C\n", temp);

    // 2. Leitura de Alertas (Ajustada para o padrão R&S: BASE.1.1.ID.CODE)
    printf("  [STATUS] Verificando Alertas...\n");
    cJSON_ArrayForEach(alert, alerts_map) {
        int code = cJSON_GetObjectItem(alert, "code")->valueint;
        const char *label = cJSON_GetObjectItem(alert, "label")->valuestring;
        
        char full_oid[256];
        // TENTATIVA: Movendo o ID para a posição correta conforme manual R&S
        snprintf(full_oid, sizeof(full_oid), "%s.1.1.%d.%d", base_status_oid, amp_id, code);
        
        int status_val = get_snmp_int(full_oid);
        printf("    %-18s: %s (%d)\n", label, translate_status(status_val), status_val);
    }
}

// --- MAIN ---
int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Uso: %s <IP_DO_TX>\n", argv[0]);
        return 1;
    }

    char *json_raw = read_file("rs_xx9.json");
    cJSON *root = cJSON_Parse(json_raw);
    cJSON *amp_table = cJSON_GetObjectItem(root, "amplifier_table");

    init_snmp_session(argv[1]);

    int discovery_list[32];
    const char *oid_temp = cJSON_GetObjectItem(amp_table, "base_oid_temp")->valuestring;
    int total_found = discover_amplifiers(oid_temp, discovery_list);

    printf("JUPITER: %d amplificadores localizados.\n", total_found);

    for (int i = 0; i < total_found; i++) {
        process_amplifier(discovery_list[i], amp_table);
    }

    snmp_close(ss);
    cJSON_Delete(root);
    free(json_raw);
    return 0;
}